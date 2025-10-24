import sys
import PyPDF2


def create_password_protected_pdf(input_pdf, output_pdf, password):
    """Encrypt a PDF file with a given password."""
    try:
        # Open the input PDF in read-binary mode
        with open(input_pdf, "rb") as file:
            pdf_reader = PyPDF2.PdfReader(file)
            pdf_writer = PyPDF2.PdfWriter()

            # Copy all pages to the writer
            for page in pdf_reader.pages:
                pdf_writer.add_page(page)

            # Apply password encryption
            pdf_writer.encrypt(password)

            # Write the encrypted PDF to the output file
            with open(output_pdf, "wb") as output:
                pdf_writer.write(output)

            print(f"[+] PDF '{output_pdf}' created successfully with password protection.")
    
    except FileNotFoundError:
        print(f"[!] Error: Input file '{input_pdf}' not found.")
    except PyPDF2.errors.PdfReadError:
        print(f"[!] Error: '{input_pdf}' is not a valid PDF file.")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")


def main():
    # Check if user provided correct arguments
    if len(sys.argv) != 4:
        print("Usage: python pdf_protect.py <input.pdf> <output.pdf> <password>")
        sys.exit(1)

    # Extract arguments
    input_pdf = sys.argv[1]
    output_pdf = sys.argv[2]
    password = sys.argv[3]

    # Run the encryption function
    create_password_protected_pdf(input_pdf, output_pdf, password)


if __name__ == "__main__":
    main()
