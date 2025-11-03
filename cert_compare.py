#!/usr/bin/env python3
"""
Certificate Comparison Tool using LLM

This tool compares two X.509 certificates using Large Language Models
to identify differences while ignoring naturally different fields like hashes.

TODO:
    - Create Streamlit UI for this application to make it more user-friendly
      Features to include:
      * File upload interface for certificates
      * Model selection dropdown
      * API key input (with option to save securely)
      * Real-time comparison progress
      * Interactive report display
      * Export report functionality
"""

import argparse
import sys
from pathlib import Path
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import openai
import google.generativeai as genai


class CertificateParser:
    """Parse X.509 certificates and convert to readable text format."""
    
    @staticmethod
    def parse_certificate(cert_path: Path) -> str:
        """Parse a certificate file and return human-readable text."""
        try:
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            
            # Try PEM format first
            try:
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            except ValueError:
                # Try DER format
                cert = x509.load_der_x509_certificate(cert_data, default_backend())
            
            return CertificateParser._format_certificate(cert, cert_path.name)
        except Exception as e:
            raise ValueError(f"Failed to parse certificate {cert_path}: {e}")
    
    @staticmethod
    def _format_certificate(cert: x509.Certificate, filename: str) -> str:
        """Format certificate details into readable text."""
        # Format serial number as hex with colons
        serial_hex = format(cert.serial_number, 'x')
        # Pad with leading zero if odd length
        if len(serial_hex) % 2:
            serial_hex = '0' + serial_hex
        serial_formatted = ':'.join(serial_hex[i:i+2] for i in range(0, len(serial_hex), 2))
        
        # Get signature algorithm name
        sig_alg_name = CertificateParser._get_algorithm_name(cert.signature_algorithm_oid)
        
        lines = [
            f"Certificate: {filename}",
            "=" * 80,
            f"Version: {cert.version.name}",
            f"Serial Number: {serial_formatted}",
            f"Signature Algorithm: {sig_alg_name}",
            "",
            "Issuer:",
            f"  {CertificateParser._format_name(cert.issuer)}",
            "",
            "Subject:",
            f"  {CertificateParser._format_name(cert.subject)}",
            "",
            "Validity:",
            f"  Not Before: {cert.not_valid_before_utc.strftime('%b %d %H:%M:%S %Y GMT')}",
            f"  Not After: {cert.not_valid_after_utc.strftime('%b %d %H:%M:%S %Y GMT')}",
            "",
            "Public Key:",
        ]
        
        # Public key info
        public_key = cert.public_key()
        if hasattr(public_key, 'key_size') and hasattr(public_key, 'curve'):
            curve_name = public_key.curve.name
            key_size = public_key.key_size
            lines.append(f"  Algorithm: ECDSA")
            lines.append(f"  Key Size: {key_size} bits")
            lines.append(f"  Curve: {curve_name} (P-{key_size})")
        elif hasattr(public_key, 'key_size'):
            lines.append(f"  Algorithm: {type(public_key).__name__}")
            lines.append(f"  Key Size: {public_key.key_size} bits")
        
        lines.append("")
        lines.append("Extensions:")
        
        # Parse extensions
        extensions_data = {}
        
        # Subject Key Identifier
        try:
            ski = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            ski_hex = ski.value.digest.hex()
            extensions_data['Subject Key Identifier'] = ':'.join(ski_hex[i:i+2].upper() for i in range(0, len(ski_hex), 2))
        except x509.ExtensionNotFound:
            pass
        
        # Authority Key Identifier
        try:
            aki = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
            if aki.value.key_identifier:
                aki_hex = aki.value.key_identifier.hex()
                extensions_data['Authority Key Identifier'] = ':'.join(aki_hex[i:i+2].upper() for i in range(0, len(aki_hex), 2))
        except x509.ExtensionNotFound:
            pass
        
        # Key Usage
        try:
            ku = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
            usages = []
            if ku.value.digital_signature:
                usages.append("Digital Signature")
            if ku.value.content_commitment:
                usages.append("Non Repudiation")
            if ku.value.key_encipherment:
                usages.append("Key Encipherment")
            if ku.value.data_encipherment:
                usages.append("Data Encipherment")
            if ku.value.key_agreement:
                usages.append("Key Agreement")
            if ku.value.key_cert_sign:
                usages.append("Key Cert Sign")
            if ku.value.crl_sign:
                usages.append("CRL Sign")
            extensions_data['Key Usage'] = ", ".join(usages) if usages else "None"
        except x509.ExtensionNotFound:
            pass
        
        # Extended Key Usage
        try:
            eku = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)
            eku_list = []
            for oid in eku.value:
                if oid == x509.oid.ExtendedKeyUsageOID.SERVER_AUTH:
                    eku_list.append("TLS Web Server Authentication")
                elif oid == x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH:
                    eku_list.append("TLS Web Client Authentication")
                elif oid == x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION:
                    eku_list.append("E-mail Protection")
                elif oid == x509.oid.ExtendedKeyUsageOID.CODE_SIGNING:
                    eku_list.append("Code Signing")
                else:
                    eku_list.append(str(oid))
            extensions_data['Extended Key Usage'] = ", ".join(eku_list) if eku_list else "Not present"
        except x509.ExtensionNotFound:
            extensions_data['Extended Key Usage'] = "Not present"
        
        # Subject Alternative Name
        try:
            san = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_list = []
            for name in san.value:
                if isinstance(name, x509.RFC822Name):
                    san_list.append(f"email:{name.value}")
                elif isinstance(name, x509.DNSName):
                    san_list.append(f"DNS:{name.value}")
            extensions_data['Subject Alternative Name'] = ", ".join(san_list) if san_list else "Not present"
        except x509.ExtensionNotFound:
            extensions_data['Subject Alternative Name'] = "Not present"
        
        # Certificate Policies
        try:
            cp = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.CERTIFICATE_POLICIES)
            policies = []
            repository_urls = []
            for policy in cp.value:
                policies.append(str(policy.policy_identifier.dotted_string))
                # Extract CPS (Certification Practice Statement) URLs
                if policy.policy_qualifiers:
                    for qualifier in policy.policy_qualifiers:
                        try:
                            if hasattr(qualifier, 'access_location') and isinstance(qualifier.access_location, x509.UniformResourceIdentifier):
                                repository_urls.append(qualifier.access_location.value)
                            elif hasattr(qualifier, 'uri'):
                                repository_urls.append(qualifier.uri)
                        except:
                            pass
            extensions_data['Certificate Policies'] = "\n  - " + "\n  - ".join(policies)
            if repository_urls:
                # Remove duplicates
                unique_repos = list(dict.fromkeys(repository_urls))
                extensions_data['Repository'] = ", ".join(unique_repos)
        except x509.ExtensionNotFound:
            extensions_data['Certificate Policies'] = "Not present"
        
        # Authority Information Access (OCSP, CA Issuers)
        try:
            aia = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            ocsp_uris = []
            ca_issuers_uris = []
            for desc in aia.value:
                if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                        ocsp_uris.append(desc.access_location.value)
                elif desc.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
                    if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                        ca_issuers_uris.append(desc.access_location.value)
            if ocsp_uris:
                extensions_data['OCSP URI'] = ", ".join(ocsp_uris)
            if ca_issuers_uris:
                extensions_data['CA Issuers URI'] = ", ".join(ca_issuers_uris)
        except x509.ExtensionNotFound:
            pass
        
        # CRL Distribution Points
        try:
            crl = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS)
            crl_uris = []
            for dp in crl.value:
                if dp.full_name:
                    for name in dp.full_name:
                        if isinstance(name, x509.UniformResourceIdentifier):
                            crl_uris.append(name.value)
            if crl_uris:
                extensions_data['CRL URI'] = ", ".join(crl_uris)
        except x509.ExtensionNotFound:
            pass
        
        # Write extensions
        for key, value in extensions_data.items():
            lines.append(f"  {key}: {value}")
        
        return "\n".join(lines)
    
    @staticmethod
    def _format_name(name: x509.Name) -> str:
        """Format X.509 Name object to string."""
        parts = []
        for attribute in name:
            oid_name = CertificateParser._get_oid_name(attribute.oid)
            parts.append(f"{oid_name} = {attribute.value}")
        return ", ".join(parts)
    
    @staticmethod
    def _get_oid_name(oid):
        """Get human-readable OID name."""
        # Common OID names
        oid_map = {
            x509.oid.NameOID.COUNTRY_NAME: "C",
            x509.oid.NameOID.STATE_OR_PROVINCE_NAME: "ST",
            x509.oid.NameOID.LOCALITY_NAME: "L",
            x509.oid.NameOID.ORGANIZATION_NAME: "O",
            x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
            x509.oid.NameOID.COMMON_NAME: "CN",
            x509.oid.NameOID.SERIAL_NUMBER: "serialNumber",
            x509.oid.NameOID.SURNAME: "SN",
            x509.oid.NameOID.GIVEN_NAME: "GN",
            x509.oid.NameOID.ORGANIZATION_IDENTIFIER: "organizationIdentifier",
        }
        return oid_map.get(oid, str(oid))
    
    @staticmethod
    def _get_algorithm_name(oid):
        """Get algorithm name from OID."""
        alg_map = {
            x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA256: "ecdsa-with-SHA256",
            x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA384: "ecdsa-with-SHA384",
            x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA512: "ecdsa-with-SHA512",
            x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA256: "sha256WithRSAEncryption",
            x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA384: "sha384WithRSAEncryption",
            x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA512: "sha512WithRSAEncryption",
        }
        return alg_map.get(oid, str(oid))


class LLMComparator:
    """Compare certificates using LLM."""
    
    def __init__(self, model: str, api_key: str):
        self.model = model.lower()
        self.api_key = api_key
        
        if self.model in ['gpt-3.5-turbo', 'gpt-4', 'gpt-4-turbo', 'chatgpt']:
            openai.api_key = api_key
            self.client = openai.OpenAI(api_key=api_key)
            # Default chatgpt to gpt-3.5-turbo as it's more widely available
            # Users can explicitly use -m gpt-4 if they have access
            self.model_name = 'gpt-3.5-turbo' if model == 'chatgpt' else model
            self.is_openai = True
        elif self.model in ['gemini', 'gemini-pro', 'gemini-1.5-pro', 'gemini-1.5-flash']:
            genai.configure(api_key=api_key)
            
            # Try to get available models first to find what works
            available_models = []
            try:
                for m in genai.list_models():
                    if 'generateContent' in m.supported_generation_methods:
                        # Extract model name (remove 'models/' prefix if present)
                        model_name = m.name.replace('models/', '')
                        available_models.append(model_name)
            except Exception:
                pass  # If listing fails, we'll try defaults
            
            # Map user-friendly names to actual model identifiers
            # Try common model name formats
            model_candidates = {
                'gemini': ['gemini-pro', 'models/gemini-pro'],
                'gemini-pro': ['gemini-pro', 'models/gemini-pro'],
                'gemini-1.5-flash': [
                    'gemini-1.5-flash-001', 'gemini-1.5-flash', 
                    'models/gemini-1.5-flash-001', 'models/gemini-1.5-flash'
                ],
                'gemini-1.5-pro': [
                    'gemini-1.5-pro-001', 'gemini-1.5-pro',
                    'models/gemini-1.5-pro-001', 'models/gemini-1.5-pro'
                ],
            }
            
            candidates = model_candidates.get(self.model, [self.model])
            
            # If we have available models list, prioritize those
            if available_models:
                # Find first candidate that matches available models
                for candidate in candidates:
                    # Try exact match
                    if candidate in available_models:
                        actual_model = candidate
                        break
                    # Try without models/ prefix
                    candidate_clean = candidate.replace('models/', '')
                    if candidate_clean in available_models:
                        actual_model = candidate_clean
                        break
                    # Try with models/ prefix
                    candidate_with_prefix = f"models/{candidate_clean}"
                    if candidate_with_prefix in available_models:
                        actual_model = candidate_with_prefix
                        break
                else:
                    # Fallback to first available model that contains gemini
                    gemini_models = [m for m in available_models if 'gemini' in m.lower()]
                    if gemini_models:
                        actual_model = gemini_models[0]
                    else:
                        actual_model = candidates[0]
            else:
                # No model list available, try candidates in order
                actual_model = candidates[0]
            
            # Try to create the model
            last_error = None
            for candidate in [actual_model] + [c for c in candidates if c != actual_model]:
                try:
                    self.client = genai.GenerativeModel(candidate)
                    break  # Success!
                except Exception as e:
                    last_error = e
                    continue
            else:
                # All candidates failed
                error_msg = f"Failed to initialize Gemini model '{self.model}'. Tried: {candidates}"
                if available_models:
                    error_msg += f"\nAvailable models: {', '.join(available_models[:5])}"
                raise RuntimeError(error_msg) from last_error
            
            self.is_openai = False
        else:
            raise ValueError(f"Unsupported model: {model}. Supported: chatgpt, gpt-4, gpt-4-turbo, gemini, gemini-pro, gemini-1.5-pro, gemini-1.5-flash")
    
    def compare_certificates(self, cert1_text: str, cert2_text: str, cert1_name: str, cert2_name: str) -> str:
        """Compare two certificates using LLM and return comparison analysis."""
        
        prompt = f"""You are a cybersecurity expert analyzing X.509 certificates. Compare the following two certificates and identify all differences, while ignoring naturally different fields like:

- Serial numbers (always unique per certificate)
- Subject Key Identifiers (always unique per certificate)
- Authority Key Identifiers (different for different CAs)
- Public keys (always unique per certificate)
- Validity periods (different issue dates are normal)
- Hash values

Focus on:
- Structural differences
- Configuration differences
- Policy differences (like UAT vs Production prefixes)
- Algorithm differences
- Extension differences
- Issuer/Subject patterns
- Service endpoint differences

Certificate 1 ({cert1_name}):
{cert1_text}

Certificate 2 ({cert2_name}):
{cert2_text}

Provide a detailed comparison in markdown format with:
1. Executive summary (with visual indicators: ✅ for good/expected, ⚠️ for warnings, ❌ for issues)
2. Field-by-field comparison table with emoji indicators:
   - ✅ for correct matches or expected differences
   - ❌ for incorrect/unexpected differences or problems
   - ⚠️ for potential issues or warnings
   - ❓ for doubtful or uncertain items
3. Key differences analysis with visual indicators
4. Expected vs unexpected differences clearly marked
5. Security implications if any (with appropriate warning indicators)
6. Conclusion with overall assessment emoji (✅=good, ⚠️=needs attention, ❌=problems found)

Use clear markdown formatting with tables, headers, and emojis throughout:
- ✅ Green checkmark for correct/expected/good
- ❌ Red X for incorrect/problems/issues
- ⚠️ Yellow warning for potential issues/warnings
- ❓ Question mark for doubtful/uncertain items
- 🔒 Security-related items
- 📋 For information/documentation
- ⚡ For important notes"""
        
        if self.is_openai:
            # Try the specified model first, fallback to gpt-3.5-turbo if it fails
            models_to_try = [self.model_name]
            if self.model_name != 'gpt-3.5-turbo':
                models_to_try.append('gpt-3.5-turbo')
            
            last_error = None
            for model_to_use in models_to_try:
                try:
                    response = self.client.chat.completions.create(
                        model=model_to_use,
                        messages=[
                            {"role": "system", "content": "You are a cybersecurity expert specializing in X.509 certificate analysis."},
                            {"role": "user", "content": prompt}
                        ],
                        temperature=0.3
                    )
                    if model_to_use != self.model_name:
                        print(f"⚠️  Note: Using {model_to_use} instead of {self.model_name} (fallback due to access/permissions)")
                    return response.choices[0].message.content
                except Exception as e:
                    last_error = e
                    error_str = str(e)
                    # If it's a model not found error and we have more models to try, continue
                    if "does not exist" in error_str or "not have access" in error_str or "model_not_found" in error_str:
                        if model_to_use != models_to_try[-1]:  # Not the last one
                            continue
                    # Otherwise, raise the error
                    raise
            
            # If we exhausted all models, raise the last error
            if last_error:
                error_msg = f"Failed to generate content with OpenAI. Tried models: {models_to_try}\n"
                error_msg += f"Last error: {last_error}\n\n"
                error_msg += "Possible solutions:\n"
                error_msg += "  1. Check your API key has access to the requested model\n"
                error_msg += "  2. Try using 'gpt-3.5-turbo' explicitly: -m gpt-3.5-turbo\n"
                error_msg += "  3. Verify your OpenAI account has credits/quota"
                raise RuntimeError(error_msg) from last_error
        else:  # Gemini
            import time
            from google.api_core import exceptions as google_exceptions
            
            max_retries = 3
            retry_delay = 1
            
            for attempt in range(max_retries):
                try:
                    response = self.client.generate_content(prompt)
                    return response.text
                except google_exceptions.ResourceExhausted as e:
                    # Quota exceeded - check if we should retry
                    error_str = str(e)
                    if 'retry_delay' in error_str or 'Please retry' in error_str:
                        # Extract retry delay if mentioned
                        if attempt < max_retries - 1:
                            try:
                                # Try to parse retry delay (usually in seconds)
                                import re
                                delay_match = re.search(r'retry in ([\d.]+)s', error_str, re.IGNORECASE)
                                if delay_match:
                                    retry_delay = float(delay_match.group(1))
                                else:
                                    # Default exponential backoff
                                    retry_delay = min(60, retry_delay * 2)
                                
                                print(f"⚠️  Quota exceeded. Waiting {retry_delay:.1f} seconds before retry {attempt + 2}/{max_retries}...")
                                time.sleep(retry_delay)
                                continue
                            except:
                                pass
                    
                    # Quota exhausted or too many retries
                    error_msg = (
                        f"❌ Gemini API quota exceeded (Free Tier limit reached).\n"
                        f"Error: {error_str[:200]}...\n\n"
                        f"Solutions:\n"
                        f"  1. Wait for your daily quota to reset\n"
                        f"  2. Upgrade to a paid plan at https://ai.google.dev\n"
                        f"  3. Use ChatGPT instead: python cert_compare.py ... -m chatgpt -k <openai-key>\n"
                        f"  4. Monitor usage at: https://ai.dev/usage?tab=rate-limit"
                    )
                    raise RuntimeError(error_msg) from e
                except Exception as e:
                    # Other errors - don't retry
                    error_msg = f"Failed to generate content with Gemini model. Error: {e}"
                    if "404" in str(e):
                        error_msg += "\n\nThis usually means the model name is incorrect or not available."
                        error_msg += "\nTry using 'chatgpt' instead or check available models."
                    raise RuntimeError(error_msg) from e
            
            # Should not reach here, but just in case
            raise RuntimeError("Failed to generate content after retries")


class ReportGenerator:
    """Generate markdown comparison report."""
    
    @staticmethod
    def generate_report(cert1_path: Path, cert2_path: Path, cert1_text: str, cert2_text: str, 
                       comparison: str, output_path: Path) -> None:
        """Generate a complete markdown report."""
        
        report = f"""# 📋 Certificate Comparison Report

## 📊 Executive Summary

This report compares two X.509 certificates using AI-powered analysis. The certificates are analyzed for structural, configuration, and policy differences while ignoring naturally unique identifiers.

**📄 Certificate 1**: {cert1_path.name}  
**📄 Certificate 2**: {cert2_path.name}  
**📅 Analysis Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## 📑 Certificate Details

### Certificate 1: {cert1_path.name}

```
{cert1_text}
```

### Certificate 2: {cert2_path.name}

```
{cert2_text}
```

---

## 🤖 AI-Powered Comparison Analysis

{comparison}

---

## 📎 Appendix: Certificate Text Files

The full certificate text representations are shown above in the Certificate Details section.

---

*📅 Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*  
*🔧 Analysis tool: Certificate Comparison Tool with LLM*
"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"Report generated: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Compare X.509 certificates using LLM analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -c1 auth-00000000006.crt -c2 auth-PRODUCTION.crt -m chatgpt -k your-api-key
  %(prog)s -c1 sign-00000000006.crt -c2 sign-PRODUCTION.crt -m gemini -k your-api-key -o report.md
        """
    )
    
    parser.add_argument('-c1', '--cert1', required=True, type=Path,
                       help='Path to first certificate file')
    parser.add_argument('-c2', '--cert2', required=True, type=Path,
                       help='Path to second certificate file')
    parser.add_argument('-m', '--model', required=True,
                       choices=['chatgpt', 'gpt-3.5-turbo', 'gpt-4', 'gpt-4-turbo', 'gemini', 'gemini-pro', 'gemini-1.5-pro', 'gemini-1.5-flash'],
                       help='LLM model to use (chatgpt, gpt-3.5-turbo, gpt-4, gpt-4-turbo, gemini, gemini-pro, gemini-1.5-pro, gemini-1.5-flash)')
    parser.add_argument('-k', '--api-key', required=True,
                       help='API key for the LLM service')
    parser.add_argument('-o', '--output', type=Path, default=None,
                       help='Output report file path (default: certificate_comparison_report_<timestamp>.md)')
    
    args = parser.parse_args()
    
    # Validate certificate files
    if not args.cert1.exists():
        print(f"Error: Certificate file not found: {args.cert1}", file=sys.stderr)
        sys.exit(1)
    
    if not args.cert2.exists():
        print(f"Error: Certificate file not found: {args.cert2}", file=sys.stderr)
        sys.exit(1)
    
    # Determine output path
    if args.output is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        args.output = Path(f"certificate_comparison_report_{timestamp}.md")
    
    try:
        # Parse certificates
        print(f"Parsing certificate 1: {args.cert1}...")
        cert1_text = CertificateParser.parse_certificate(args.cert1)
        
        print(f"Parsing certificate 2: {args.cert2}...")
        cert2_text = CertificateParser.parse_certificate(args.cert2)
        
        # Compare using LLM
        print(f"Comparing certificates using {args.model}...")
        comparator = LLMComparator(args.model, args.api_key)
        comparison = comparator.compare_certificates(
            cert1_text, cert2_text, 
            args.cert1.name, args.cert2.name
        )
        
        # Generate report
        print(f"Generating report: {args.output}...")
        ReportGenerator.generate_report(
            args.cert1, args.cert2,
            cert1_text, cert2_text,
            comparison, args.output
        )
        
        print("✓ Comparison complete!")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()

