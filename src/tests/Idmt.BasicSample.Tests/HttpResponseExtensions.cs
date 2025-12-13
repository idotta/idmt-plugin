namespace Idmt.BasicSample.Tests;

public static class HttpResponseExtensions
{
    public static async Task AssertSuccess(this HttpResponseMessage response)
    {
        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync();
            throw new Xunit.Sdk.XunitException($"Expected success for {response.RequestMessage?.Method} {response.RequestMessage?.RequestUri} but got {(int)response.StatusCode} {response.StatusCode}. Body: {body}");
        }
    }
}
