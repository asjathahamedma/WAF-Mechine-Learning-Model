using System.Text.Json.Serialization;

namespace SmartEventMVC.Services;

public class WafCheckRequest
{
    [JsonPropertyName("method")]
    public string Method { get; set; } = "GET";

    [JsonPropertyName("path")]
    public string Path { get; set; } = "/";

    [JsonPropertyName("queryString")]
    public string QueryString { get; set; } = "";

    [JsonPropertyName("body")]
    public string Body { get; set; } = "";

    [JsonPropertyName("threshold")]
    public double Threshold { get; set; } = 0.70;
}

public class WafDecision
{
    [JsonPropertyName("request")]
    public string Request { get; set; } = "";

    public int Prediction { get; set; }

    [JsonPropertyName("probability_malicious")]
    public double ProbabilityMalicious { get; set; }

    [JsonPropertyName("rule_based_malicious")]
    public int RuleBasedMalicious { get; set; }

    [JsonPropertyName("rule_based_safe")]
    public int RuleBasedSafe { get; set; }

    [JsonPropertyName("rule_reason")]
    public string RuleReason { get; set; } = "model_only";

    public string Action { get; set; } = "allow";
    public double Threshold { get; set; }
}
