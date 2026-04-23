using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace SmartEventMVC.Services;

public class WafClient
{
    private readonly HttpClient _httpClient;
    private readonly WafOptions _options;

    public WafClient(HttpClient httpClient, IOptions<WafOptions> options)
    {
        _httpClient = httpClient;
        _options = options.Value;
        _httpClient.Timeout = TimeSpan.FromSeconds(_options.RequestTimeoutSeconds);
    }

    public async Task<WafDecision?> CheckAsync(WafCheckRequest request, CancellationToken cancellationToken)
    {
        // Send explicit JSON so the Python API receives the exact request fields from MVC.
        var json = JsonSerializer.Serialize(request);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await _httpClient.PostAsync(_options.ApiUrl, content, cancellationToken);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<WafDecision>(cancellationToken: cancellationToken);
    }
}
