namespace SmartEventMVC.Services;

public class WafOptions
{
    public bool Enabled { get; set; } = true;
    public string ApiUrl { get; set; } = "http://127.0.0.1:8765/check";
    public bool FailOpen { get; set; } = true;
    public bool InspectGet { get; set; } = true;
    public bool InspectPost { get; set; } = true;
    public double PredictionThreshold { get; set; } = 0.70;
    public int RequestTimeoutSeconds { get; set; } = 10;
}
