using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace mRemoteNG.Tools.SecurityScanner
{
    /// <summary>
    /// Supported LLM providers for security analysis.
    /// </summary>
    public enum LlmProvider
    {
        OpenAI,
        Claude,
        Gemini,
        Grok
    }

    /// <summary>
    /// Configuration for the LLM security analyzer.
    /// </summary>
    public class LlmConfig
    {
        public LlmProvider Provider { get; set; } = LlmProvider.OpenAI;
        public string ApiKey { get; set; } = "";
        public string Model { get; set; } = "";

        /// <summary>
        /// Gets the default model name for the given provider.
        /// </summary>
        public static string GetDefaultModel(LlmProvider provider) => provider switch
        {
            LlmProvider.OpenAI => "gpt-4o",
            LlmProvider.Claude => "claude-sonnet-4-20250514",
            LlmProvider.Gemini => "gemini-2.0-flash",
            LlmProvider.Grok => "grok-3",
            _ => "gpt-4o"
        };
    }

    /// <summary>
    /// Sends system security data to an LLM provider for analysis and returns
    /// actionable security findings and remediation steps.
    /// </summary>
    public class LlmSecurityAnalyzer
    {
        private static readonly HttpClient SharedHttpClient = new() { Timeout = TimeSpan.FromMinutes(5) };

        private const string SystemPrompt = @"You are an expert cybersecurity analyst performing a comprehensive security audit of a computer system. You have been provided with detailed system information including OS details, running processes, network connections, installed software, firewall status, user accounts, update history, shared folders, startup programs, and antivirus status.

Analyze the provided system data and produce a detailed security report with the following sections:

1. **CRITICAL ISSUES** - Vulnerabilities that need immediate attention (e.g., outdated software with known CVEs, disabled firewall, open dangerous ports, admin accounts without passwords)

2. **HIGH RISK FINDINGS** - Significant security concerns (e.g., unnecessary services running, suspicious processes, weak configurations)

3. **MEDIUM RISK FINDINGS** - Issues that should be addressed in a timely manner (e.g., missing updates, unnecessary shared folders, startup programs that could be malware vectors)

4. **LOW RISK / INFORMATIONAL** - Best practice recommendations and hardening suggestions

5. **REMEDIATION STEPS** - For each finding, provide specific, actionable steps to fix the issue. Include PowerShell commands, Group Policy settings, or registry changes where applicable.

6. **OVERALL SECURITY SCORE** - Rate the system security from 1-10 with justification.

Be specific about CVEs where applicable. Reference the actual process names, ports, and software versions from the scan data. Do not make assumptions - only report on what you can see in the data.";

        public async Task<string> AnalyzeAsync(string systemData, LlmConfig config, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(config.ApiKey))
                throw new ArgumentException("API key is required for LLM analysis.");

            string model = string.IsNullOrEmpty(config.Model)
                ? LlmConfig.GetDefaultModel(config.Provider)
                : config.Model;

            return config.Provider switch
            {
                LlmProvider.OpenAI => await CallOpenAiAsync(systemData, config.ApiKey, model, cancellationToken),
                LlmProvider.Claude => await CallClaudeAsync(systemData, config.ApiKey, model, cancellationToken),
                LlmProvider.Gemini => await CallGeminiAsync(systemData, config.ApiKey, model, cancellationToken),
                LlmProvider.Grok => await CallGrokAsync(systemData, config.ApiKey, model, cancellationToken),
                _ => throw new ArgumentOutOfRangeException(nameof(config.Provider))
            };
        }

        private async Task<string> CallOpenAiAsync(string systemData, string apiKey, string model, CancellationToken ct)
        {
            var requestBody = new
            {
                model,
                messages = new[]
                {
                    new { role = "system", content = SystemPrompt },
                    new { role = "user", content = $"Please analyze the following system security scan data:\n\n{systemData}" }
                },
                max_tokens = 8000,
                temperature = 0.1
            };

            using HttpRequestMessage request = new(HttpMethod.Post, "https://api.openai.com/v1/chat/completions");
            request.Headers.Add("Authorization", $"Bearer {apiKey}");
            request.Content = new StringContent(JsonConvert.SerializeObject(requestBody), Encoding.UTF8, "application/json");

            HttpResponseMessage response = await SharedHttpClient.SendAsync(request, ct);
            string responseBody = await response.Content.ReadAsStringAsync(ct);

            if (!response.IsSuccessStatusCode)
                throw new HttpRequestException($"OpenAI API error ({response.StatusCode}): {responseBody}");

            JObject json = JObject.Parse(responseBody);
            return json["choices"]?[0]?["message"]?["content"]?.ToString()
                ?? "No response content received from OpenAI.";
        }

        private async Task<string> CallClaudeAsync(string systemData, string apiKey, string model, CancellationToken ct)
        {
            var requestBody = new
            {
                model,
                max_tokens = 8000,
                system = SystemPrompt,
                messages = new[]
                {
                    new { role = "user", content = $"Please analyze the following system security scan data:\n\n{systemData}" }
                }
            };

            using HttpRequestMessage request = new(HttpMethod.Post, "https://api.anthropic.com/v1/messages");
            request.Headers.Add("x-api-key", apiKey);
            request.Headers.Add("anthropic-version", "2023-06-01");
            request.Content = new StringContent(JsonConvert.SerializeObject(requestBody), Encoding.UTF8, "application/json");

            HttpResponseMessage response = await SharedHttpClient.SendAsync(request, ct);
            string responseBody = await response.Content.ReadAsStringAsync(ct);

            if (!response.IsSuccessStatusCode)
                throw new HttpRequestException($"Claude API error ({response.StatusCode}): {responseBody}");

            JObject json = JObject.Parse(responseBody);
            return json["content"]?[0]?["text"]?.ToString()
                ?? "No response content received from Claude.";
        }

        private async Task<string> CallGeminiAsync(string systemData, string apiKey, string model, CancellationToken ct)
        {
            string url = $"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={apiKey}";

            var requestBody = new
            {
                system_instruction = new
                {
                    parts = new[] { new { text = SystemPrompt } }
                },
                contents = new[]
                {
                    new
                    {
                        parts = new[]
                        {
                            new { text = $"Please analyze the following system security scan data:\n\n{systemData}" }
                        }
                    }
                },
                generationConfig = new
                {
                    maxOutputTokens = 8000,
                    temperature = 0.1
                }
            };

            using HttpRequestMessage request = new(HttpMethod.Post, url);
            request.Content = new StringContent(JsonConvert.SerializeObject(requestBody), Encoding.UTF8, "application/json");

            HttpResponseMessage response = await SharedHttpClient.SendAsync(request, ct);
            string responseBody = await response.Content.ReadAsStringAsync(ct);

            if (!response.IsSuccessStatusCode)
                throw new HttpRequestException($"Gemini API error ({response.StatusCode}): {responseBody}");

            JObject json = JObject.Parse(responseBody);
            return json["candidates"]?[0]?["content"]?["parts"]?[0]?["text"]?.ToString()
                ?? "No response content received from Gemini.";
        }

        private async Task<string> CallGrokAsync(string systemData, string apiKey, string model, CancellationToken ct)
        {
            // Grok uses OpenAI-compatible API format via xAI
            var requestBody = new
            {
                model,
                messages = new[]
                {
                    new { role = "system", content = SystemPrompt },
                    new { role = "user", content = $"Please analyze the following system security scan data:\n\n{systemData}" }
                },
                max_tokens = 8000,
                temperature = 0.1
            };

            using HttpRequestMessage request = new(HttpMethod.Post, "https://api.x.ai/v1/chat/completions");
            request.Headers.Add("Authorization", $"Bearer {apiKey}");
            request.Content = new StringContent(JsonConvert.SerializeObject(requestBody), Encoding.UTF8, "application/json");

            HttpResponseMessage response = await SharedHttpClient.SendAsync(request, ct);
            string responseBody = await response.Content.ReadAsStringAsync(ct);

            if (!response.IsSuccessStatusCode)
                throw new HttpRequestException($"Grok API error ({response.StatusCode}): {responseBody}");

            JObject json = JObject.Parse(responseBody);
            return json["choices"]?[0]?["message"]?["content"]?.ToString()
                ?? "No response content received from Grok.";
        }
    }
}
