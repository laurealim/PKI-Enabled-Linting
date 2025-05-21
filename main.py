from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timezone

def check_certificate_validity(cert_path):
   
    try:
        # 1. Load the certificate from the file
        with open(cert_path, "rb") as f:
            cert_data = f.read()

        # Detect PEM or DER
        if cert_data.startswith(b"-----BEGIN CERTIFICATE-----"):
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        else:
            cert = x509.load_der_x509_certificate(cert_data, default_backend())

        print(f"--- Certificate Analysis: {cert_path} ---")
        print(f"\nSubject: {cert.subject.rfc4514_string()}")
        print(f"Issuer: {cert.issuer.rfc4514_string()}")
        print(f"Serial Number: {cert.serial_number}")
        print(f"Version: {cert.version}")
        print(f"Signature Algorithm: {cert.signature_algorithm_oid._name}")
        print(f"Public Key Algorithm: {cert.public_key().__class__.__name__}")
        print(f"Fingerprint (SHA256): {cert.fingerprint(hashes.SHA256()).hex()}")

        # 2. Check Temporal Validity
        print("\n--- Temporal Validity Check ---")
        now = datetime.now(timezone.utc)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        # If properties are naive, assume UTC
        if not_before.tzinfo is None:
            not_before = not_before.replace(tzinfo=timezone.utc)
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
        is_valid_now = not_before <= now <= not_after

        print(f"  Valid From: {not_before}")
        print(f"  Valid Until: {not_after}")

        if is_valid_now:
            print("  [PASS] Certificate is currently within its validity period.")
        else:
            print("  [FAIL] Certificate is NOT currently valid based on dates!")
            if now < not_before:
                print("    Reason: Not yet valid (future dated).")
            else:
                print("    Reason: Expired.")

        # 3. Check Common Extensions (Linting aspect for CA certificates)
        print("\n--- Extension Checks (Common for CAs) ---")

        # Basic Constraints (Is this a CA certificate?)
        try:
            basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            if basic_constraints.value.ca:
                print(f"  [PASS] Basic Constraints: This is a CA certificate (CA=True).")
                print(f"    Path Length Constraint: {basic_constraints.value.path_length}")
            else:
                print("  [FAIL] Basic Constraints: This is an End-Entity certificate (CA=False).")
        except x509.ExtensionNotFound:
            print("  [INFO] Basic Constraints extension not found (might be implied for root CAs or an issue for intermediate CAs).")
        except Exception as e:
            print(f"  [ERROR] Problem with Basic Constraints: {e}")

        # Key Usage (What can this key be used for?)
        try:
            key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
            print(f"  Key Usage: {key_usage.value}")
            if key_usage.value.key_cert_sign:
                print("    [PASS] Key Certificate Signing is enabled (expected for a CA).")
            else:
                print("    [WARNING] Key Certificate Signing is NOT enabled (unexpected for a CA).")
            if key_usage.value.crl_sign:
                print("    [PASS] CRL Signing is enabled (expected for a CA).")
            else:
                print("    [WARNING] CRL Signing is NOT enabled (unexpected for a CA).")
        except x509.ExtensionNotFound:
            print("  [INFO] Key Usage extension not found.")
        except Exception as e:
            print(f"  [ERROR] Problem with Key Usage: {e}")

        # Subject Key Identifier (Should be present)
        try:
            ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            print(f"  [PASS] Subject Key Identifier (SKI) found: {ski.value.digest.hex()}")
        except x509.ExtensionNotFound:
            print("  [WARNING] Subject Key Identifier (SKI) extension not found.")
        except Exception as e:
            print(f"  [ERROR] Problem with Subject Key Identifier: {e}")

        # Authority Key Identifier (Should be present and match Issuer's SKI)
        try:
            aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
            print(f"  [PASS] Authority Key Identifier (AKI) found.")
            if aki.value.key_identifier:
                print(f"    Key Identifier: {aki.value.key_identifier.hex()}")
            if aki.value.authority_cert_issuer:
                print(f"    Authority Cert Issuer: {aki.value.authority_cert_issuer}")
            if aki.value.authority_cert_serial_number:
                print(f"    Authority Cert Serial: {aki.value.authority_cert_serial_number}")
        except x509.ExtensionNotFound:
            print("  [INFO] Authority Key Identifier (AKI) extension not found (common for self-signed root CAs).")
        except Exception as e:
            print(f"  [ERROR] Problem with Authority Key Identifier: {e}")

        # CRL Distribution Points (Where to find CRLs)
        try:
            crl_dist_points = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
            print("\n--- CRL Distribution Points ---")
            for dist_point in crl_dist_points.value:
                if dist_point.full_name:
                    for full_name in dist_point.full_name:
                        print(f"  [INFO] CRL URL: {full_name.value}")
        except x509.ExtensionNotFound:
            print("  [INFO] CRL Distribution Points extension not found.")
        except Exception as e:
            print(f"  [ERROR] Problem with CRL Distribution Points: {e}")

        print("\n--- Basic Linting/Validation Summary ---")
        print("Certificate successfully parsed and basic structural/temporal checks performed.")
        print("For full RFC/CA/Browser Forum compliance 'linting' and complete chain validation (including real-time revocation checks against a trusted root store), more specialized tools or complex logic are required.")

    except FileNotFoundError:
        print(f"Error: Certificate file not found at '{cert_path}'. Please ensure the file is in the same directory.")
    except ValueError as ve:
        print(f"Error loading certificate: {ve}. Ensure it's a valid DER or PEM encoded X.509 certificate.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# --- How to use the code ---
if __name__ == "__main__":
    # Specify the path to your certificate file
    certificate_file_path = "Root_CA_Bangladesh_2020.cer"

    print(f"Attempting to perform basic linting/validation on: {certificate_file_path}")
    check_certificate_validity(certificate_file_path)