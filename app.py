import gradio as gr
from fastapi import FastAPI
from llmguardian import SecurityScanner  # Import the SecurityScanner class from the LLMGuardian package
import uvicorn

# Create the web application
app = FastAPI()

# Create the security scanner
scanner = SecurityScanner()

# Create a simple interface
def check_security(model_name, input_text):
    """
    This function creates the web interface where users can test their models
    """
    results = scanner.scan_model(model_name, input_text)
    return results.format_report()

# Create the web interface
interface = gr.Interface(
    fn=check_security,
    inputs=[
        gr.Textbox(label="Model Name"),
        gr.Textbox(label="Test Input")
    ],
    outputs=gr.JSON(label="Security Report"),
    title="LLMGuardian Security Scanner",
    description="Test your LLM model for security vulnerabilities"
)

# Mount the interface
app = gr.mount_gradio_app(app, interface, path="/")

# Ensure the FastAPI app runs when the script is executed
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)