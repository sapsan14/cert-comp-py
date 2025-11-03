# cert-comp-py

Certificate Comparison Tool - A Python tool that compares X.509 certificates using Large Language Models (LLM) to identify differences while intelligently ignoring naturally unique fields like hashes and serial numbers.

## Features

- 📄 Parse X.509 certificates (PEM and DER formats)
- 🤖 Compare certificates using ChatGPT (OpenAI) or Gemini (Google)
- 📊 Generate detailed markdown comparison reports
- ✅ Intelligently ignores naturally different fields (hashes, serial numbers, etc.)
- 🔍 Focuses on meaningful differences (configurations, policies, algorithms)

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Get API keys:
   - **OpenAI (ChatGPT)**: Get your API key from https://platform.openai.com/api-keys (paid)
   - **Google (Gemini)**: Get your API key from https://makersuite.google.com/app/apikey (free tier available)

### Free LLM API Alternatives

Free LLM APIs are available! While OpenAI requires payment, there are reliable free alternatives you can use:

#### Hugging Face Inference API
- **Website**: https://huggingface.co
- **Free tier**: Available for many models
- **How to use**: Get your API token from https://huggingface.co/settings/tokens
- **Note**: Support for Hugging Face models can be added to this tool with additional implementation

#### Other Free Options
- **Ollama**: Local models that run on your machine
- **Together AI**: Free tier available
- **Groq**: Fast free inference for open models
- **Anthropic Claude**: Free tier may be available (check current offerings)

**Tip**: If you're hitting quota limits with Gemini's free tier, consider these alternatives or upgrading to a paid plan.

## Usage

### Basic Usage

```bash
python cert_compare.py \
  -c1 auth-00000000006.crt \
  -c2 auth-PRODUCTION.crt \
  -m chatgpt \
  -k your-openai-api-key
```

### Using Gemini

```bash
python cert_compare.py \
  -c1 sign-00000000006.crt \
  -c2 sign-PRODUCTION.crt \
  -m gemini \
  -k your-gemini-api-key \
  -o my_report.md
```

### Command Line Options

- `-c1, --cert1`: Path to first certificate file (required)
- `-c2, --cert2`: Path to second certificate file (required)
- `-m, --model`: LLM model to use (required)
  - Options: `chatgpt`, `gpt-3.5-turbo`, `gpt-4`, `gpt-4-turbo`, `gemini`, `gemini-pro`, `gemini-1.5-pro`, `gemini-1.5-flash`
- `-k, --api-key`: API key for the LLM service (required)
- `-o, --output`: Output report file path (optional, defaults to `certificate_comparison_report_<timestamp>.md`)

### Examples

**Compare UAT and Production authentication certificates:**
```bash
python cert_compare.py \
  -c1 auth-00000000006.crt \
  -c2 auth-PRODUCTION.crt \
  -m gpt-4 \
  -k sk-your-key-here
```

**Compare signature certificates with custom output:**
```bash
python cert_compare.py \
  -c1 sign-00000000006.crt \
  -c2 sign-PRODUCTION.crt \
  -m gemini-pro \
  -k your-gemini-key \
  -o signature_comparison.md
```

## Supported Models

### OpenAI Models
- `chatgpt` or `gpt-4`: Uses GPT-4
- `gpt-3.5-turbo`: Uses GPT-3.5 Turbo
- `gpt-4-turbo`: Uses GPT-4 Turbo

### Google Models
- `gemini` or `gemini-pro`: Uses Gemini 1.5 Flash (deprecated names mapped to flash)
- `gemini-1.5-flash`: Uses Gemini 1.5 Flash (faster, cheaper)
- `gemini-1.5-pro`: Uses Gemini 1.5 Pro (more capable)

## Output Format

The tool generates a markdown report containing:

1. **Executive Summary**: Overview of the comparison
2. **Certificate Details**: Full text representation of both certificates
3. **AI-Powered Comparison Analysis**: Detailed LLM analysis including:
   - Field-by-field comparison tables
   - Key differences analysis
   - Expected vs unexpected differences
   - Security implications
   - Conclusion

## How It Works

1. **Certificate Parsing**: Uses the `cryptography` library to parse X.509 certificates and extract all relevant fields
2. **Text Conversion**: Converts certificates to human-readable text format
3. **LLM Analysis**: Sends certificate text to the selected LLM with instructions to compare while ignoring naturally unique fields
4. **Report Generation**: Combines certificate details and LLM analysis into a comprehensive markdown report

## Fields Automatically Ignored

The tool instructs the LLM to ignore these naturally different fields:
- Serial numbers (always unique per certificate)
- Subject Key Identifiers (always unique per certificate)
- Authority Key Identifiers (different for different CAs)
- Public keys (always unique per certificate)
- Validity periods (different issue dates are normal)
- Hash values

## Requirements

- Python 3.7+
- See `requirements.txt` for Python dependencies

## Future Enhancements

### TODO
- **Streamlit UI**: Create a web-based user interface using Streamlit
  - File upload interface for certificates
  - Model selection dropdown (ChatGPT, Gemini, etc.)
  - API key input with secure storage option
  - Real-time comparison progress indicator
  - Interactive markdown report display
  - Export functionality for reports
  - Side-by-side certificate comparison view

- **Additional LLM Support**: Add support for free LLM APIs
  - Hugging Face Inference API
  - Ollama (local models)
  - Together AI
  - Groq

- **Batch Processing**: Support comparing multiple certificate pairs at once

## License

This project is provided as-is for certificate comparison and analysis purposes.
