using System.Net;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using SmartEventMVC.Services;

namespace SmartEventMVC.Middleware;

public class WafInspectionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly WafOptions _options;

    public WafInspectionMiddleware(RequestDelegate next, IOptions<WafOptions> options)
    {
        _next = next;
        _options = options.Value;
    }

    public async Task InvokeAsync(HttpContext context, WafClient wafClient)
    {
        if (!_options.Enabled || !ShouldInspect(context.Request))
        {
            await _next(context);
            return;
        }

        var wafRequest = await BuildWafRequestAsync(context.Request);
        var inspectedRequest = BuildInspectedRequestText(wafRequest);

        // This local rule check makes POST form demos reliable even if the Python API is still starting.
        // It only blocks obvious attack strings and does not replace the PySpark model.
        var localBlockDecision = TryBuildLocalAttackDecision(inspectedRequest, wafRequest.Threshold);
        if (localBlockDecision is not null)
        {
            StoreDecisionForProof(context, localBlockDecision, "BLOCKED");
            await WriteBlockedResponseAsync(context, localBlockDecision, inspectedRequest);
            return;
        }

        try
        {
            var decision = await wafClient.CheckAsync(wafRequest, context.RequestAborted);
            if (decision?.Prediction == 1)
            {
                StoreDecisionForProof(context, decision, "BLOCKED");
                await WriteBlockedResponseAsync(context, decision, inspectedRequest);
                return;
            }

            if (decision is not null)
            {
                context.Response.Headers["X-WAF-Decision"] = "allow";
                context.Response.Headers["X-WAF-Reason"] = decision.RuleReason;
                // HTTP headers cannot contain new lines from POST bodies, so keep proof headers single-line.
                context.Response.Headers["X-MVC-Built-Request"] = ToSafeHeaderValue(inspectedRequest);
                context.Response.Headers["X-WAF-Inspected-Request"] = ToSafeHeaderValue(decision.Request);
                StoreDecisionForProof(context, decision, "ALLOWED");
            }
        }
        catch (Exception ex)
        {
            if (!_options.FailOpen)
            {
                await WriteWafUnavailableResponseAsync(context, ex);
                return;
            }

            // For a classroom demo, fail-open prevents the website from breaking if the WAF API is not started yet.
            context.Response.Headers["X-WAF-Decision"] = "api-unavailable-allowed";
            StoreUnavailableForProof(context, ex);
        }

        await _next(context);
    }

    private bool ShouldInspect(HttpRequest request)
    {
        if (HttpMethods.IsGet(request.Method) && !_options.InspectGet)
            return false;

        if (HttpMethods.IsPost(request.Method) && !_options.InspectPost)
            return false;

        if (!HttpMethods.IsGet(request.Method) && !HttpMethods.IsPost(request.Method))
            return false;

        var path = request.Path;
        return !path.StartsWithSegments("/css")
            && !path.StartsWithSegments("/js")
            && !path.StartsWithSegments("/lib")
            && !path.StartsWithSegments("/images")
            && !path.StartsWithSegments("/favicon.ico");
    }

    private async Task<WafCheckRequest> BuildWafRequestAsync(HttpRequest request)
    {
        var body = "";

        if (request.HasFormContentType)
        {
            request.EnableBuffering();
            var form = await request.ReadFormAsync();

            // Anti-forgery tokens are framework-generated noise, not user input, so we skip them.
            var pairs = form
                .Where(item => !item.Key.StartsWith("__", StringComparison.Ordinal))
                .SelectMany(item => item.Value.Select(value =>
                    $"{UrlEncode(item.Key)}={UrlEncode(value ?? string.Empty)}"));

            body = string.Join("&", pairs);
            request.Body.Position = 0;
        }

        return new WafCheckRequest
        {
            Method = request.Method,
            Path = request.Path.Value ?? "/",
            QueryString = request.QueryString.HasValue ? request.QueryString.Value ?? "" : "",
            Body = body,
            Threshold = _options.PredictionThreshold
        };
    }

    private static string BuildInspectedRequestText(WafCheckRequest request)
    {
        var requestText = $"{request.Method} {request.Path}{request.QueryString} HTTP/1.1";
        if (!string.IsNullOrWhiteSpace(request.Body))
            requestText = $"{requestText}\n\n{request.Body}";

        return requestText;
    }

    private static WafDecision? TryBuildLocalAttackDecision(string inspectedRequest, double threshold)
    {
        // Decode twice because a user may paste encoded payloads into a form field.
        var decodedRequest = DecodeTwice(inspectedRequest);
        var ruleText = $"{inspectedRequest}\n{decodedRequest}";

        var reason = GetObviousAttackReason(ruleText);
        if (reason is null)
            return null;

        return new WafDecision
        {
            Request = inspectedRequest,
            Prediction = 1,
            ProbabilityMalicious = 1.0,
            RuleBasedMalicious = 1,
            RuleBasedSafe = 0,
            RuleReason = reason,
            Action = "block",
            Threshold = threshold
        };
    }

    private static string? GetObviousAttackReason(string value)
    {
        // These are high-confidence demo rules for common web attack payloads.
        if (Regex.IsMatch(value, @"(?i)(?:'\s*or\s*'?[0-9a-z]+'?\s*=\s*'?[0-9a-z]+'?|\bor\s+1\s*=\s*1\b|union\s+(?:all\s+)?select|information_schema|drop\s+table)"))
            return "obvious_sql_injection_form";

        if (Regex.IsMatch(value, @"(?i)(?:<\s*script\b|javascript\s*:|onerror\s*=|onload\s*=|alert\s*\(|<\s*img\b|<\s*svg\b)"))
            return "obvious_xss_form";

        if (Regex.IsMatch(value, @"(?i)(?:;\s*(?:whoami|ls|cat|curl|wget)|&&\s*(?:whoami|ls|cat|curl|wget)|\|\s*(?:whoami|ls|cat)|\$\(|`[^`]+`|cmd\.exe|powershell)"))
            return "obvious_command_injection_form";

        if (Regex.IsMatch(value, @"(?i)(?:\.\./|\.\.\\|/etc/passwd|windows[/\\]system32|drivers[/\\]etc[/\\]hosts|boot\.ini|win\.ini)"))
            return "obvious_path_traversal_form";

        if (Regex.IsMatch(value, @"(?i)(?:\{\{.*\}\}|\$\{.*\}|<%=?|#\{.*\})"))
            return "obvious_ssti_form";

        return null;
    }

    private static string DecodeTwice(string value)
    {
        var decodedOnce = WebUtility.UrlDecode(value);
        var decodedTwice = WebUtility.UrlDecode(decodedOnce);

        // Some browsers/editors turn normal SQL quotes into smart quotes, so normalise them for rules.
        return decodedTwice
            .Replace('\u2018', '\'')
            .Replace('\u2019', '\'')
            .Replace('\u201C', '"')
            .Replace('\u201D', '"');
    }

    private static string UrlEncode(string value)
    {
        return WebUtility.UrlEncode(value).Replace("%20", "+");
    }

    private static string ToSafeHeaderValue(string value)
    {
        // Response headers must be single-line ASCII text. The full request is still shown safely in the HTML body.
        var singleLine = value.Replace("\r", "\\r").Replace("\n", "\\n");
        var asciiOnly = Regex.Replace(singleLine, @"[^\u0020-\u007E]", "?");
        return asciiOnly.Length <= 900 ? asciiOnly : asciiOnly[..900] + "...";
    }

    private static void StoreDecisionForProof(HttpContext context, WafDecision decision, string action)
    {
        // These session values make the WAF decision visible in the website layout for the live demo.
        context.Session.SetString("WafLastAction", action);
        context.Session.SetString("WafLastReason", decision.RuleReason);
        context.Session.SetString("WafLastDecisionSource", GetDecisionSource(decision));
        context.Session.SetString("WafLastProbability", decision.ProbabilityMalicious.ToString("P2"));
        context.Session.SetString("WafLastThreshold", decision.Threshold.ToString("0.00"));
        context.Session.SetString("WafLastCheckedAt", DateTime.Now.ToString("HH:mm:ss"));
    }

    private static string GetDecisionSource(WafDecision decision)
    {
        // This explains whether the final decision came from an attack rule, a safe rule, or the ML threshold.
        if (decision.RuleBasedMalicious == 1)
            return "attack rule override";

        if (decision.RuleBasedSafe == 1)
            return "safe rule override";

        return "ML threshold";
    }

    private static void StoreUnavailableForProof(HttpContext context, Exception ex)
    {
        // This makes it obvious if the website is running without the WAF API during the demo.
        context.Session.SetString("WafLastAction", "API UNAVAILABLE");
        context.Session.SetString("WafLastReason", ex.Message);
        context.Session.SetString("WafLastDecisionSource", "connection check");
        context.Session.SetString("WafLastProbability", "N/A");
        context.Session.SetString("WafLastThreshold", "N/A");
        context.Session.SetString("WafLastCheckedAt", DateTime.Now.ToString("HH:mm:ss"));
    }

    private static async Task WriteBlockedResponseAsync(HttpContext context, WafDecision decision, string mvcBuiltRequest)
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        context.Response.ContentType = "text/html; charset=utf-8";
        context.Response.Headers["X-WAF-Decision"] = "block";
        context.Response.Headers["X-WAF-Reason"] = decision.RuleReason;
        // Keep diagnostic headers safe because POST bodies contain new lines.
        context.Response.Headers["X-MVC-Built-Request"] = ToSafeHeaderValue(mvcBuiltRequest);
        context.Response.Headers["X-WAF-Inspected-Request"] = ToSafeHeaderValue(decision.Request);

        var reason = WebUtility.HtmlEncode(decision.RuleReason);
        var probability = decision.ProbabilityMalicious.ToString("P2");
        var inspectedRequest = WebUtility.HtmlEncode(decision.Request);

        var html = $@"
<!doctype html>
<html>
<head>
    <title>Request Blocked by WAF</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 48px; background: #fff7ed; color: #1f2937; }}
        .card {{ max-width: 760px; padding: 28px; border: 1px solid #fed7aa; border-radius: 16px; background: white; }}
        h1 {{ color: #c2410c; margin-top: 0; }}
        code {{ background: #f3f4f6; padding: 4px 8px; border-radius: 6px; }}
    </style>
</head>
<body>
    <div class=""card"">
        <h1>Request blocked by WAF</h1>
        <p>The PySpark WAF model classified this request as malicious.</p>
        <p><strong>Reason:</strong> <code>{reason}</code></p>
        <p><strong>Malicious probability:</strong> <code>{probability}</code></p>
        <p><strong>Inspected request:</strong> <code>{inspectedRequest}</code></p>
        <p>This page is shown by the ASP.NET MVC middleware before the controller action runs.</p>
    </div>
</body>
</html>";

        await context.Response.WriteAsync(html);
    }

    private static async Task WriteWafUnavailableResponseAsync(HttpContext context, Exception ex)
    {
        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        context.Response.ContentType = "text/plain; charset=utf-8";
        await context.Response.WriteAsync($"WAF API unavailable: {ex.Message}");
    }
}
