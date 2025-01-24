# Running in Huggingface

To run the LLMGuardian application on Huggingface, follow these steps:

## Setting Up the Environment

1. **Fork the Repository**:
   - Fork the LLMGuardian repository to your own GitHub account.

2. **Clone the Repository**:
   ```sh
   git clone https://github.com/your-username/LLMGuardian.git
   cd LLMGuardian
   ```

3. **Create and Activate a Virtual Environment**:
   ```sh
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

4. **Install Dependencies**:
   ```sh
   pip install -r requirements/base.txt
   ```

## Setting Up the Backend (FastAPI)

1. **Create FastAPI Backend**:
   - Implement model scanning endpoints.
   - Add prompt injection detection.
   - Include input/output validation.
   - Implement rate limiting middleware.
   - Add authentication checks.

2. **Install FastAPI and Uvicorn**:
   ```sh
   pip install fastapi uvicorn
   ```

3. **Create `main.py` for FastAPI**:
   ```python
   from fastapi import FastAPI, HTTPException

   app = FastAPI()

   @app.get("/")
   async def read_root():
       return {"message": "Welcome to LLMGuardian"}

   # Add your endpoints here

   if __name__ == "__main__":
       import uvicorn
       uvicorn.run(app, host="0.0.0.0", port=8000)
   ```

4. **Run the FastAPI Server**:
   ```sh
   uvicorn main:app --reload
   ```

## Setting Up the Frontend (Gradio)

1. **Create Gradio UI Frontend**:
   - Implement model security testing interface.
   - Add vulnerability scanning dashboard.
   - Include real-time attack detection.
   - Add configuration settings.

2. **Install Gradio**:
   ```sh
   pip install gradio
   ```

3. **Create `app.py` for Gradio**:
   ```python
   import gradio as gr

   def security_test_interface(prompt):
       # Implement your security test logic here
       return "Security test result"

   iface = gr.Interface(fn=security_test_interface, inputs="text", outputs="text")
   iface.launch()
   ```

4. **Run the Gradio Interface**:
   ```sh
   python app.py
   ```

## Deploying to Huggingface Spaces

1. **Create a New Space**:
   - Go to [Huggingface Spaces](https://huggingface.co/spaces) and create a new Space.
   - Choose Gradio as the SDK.

2. **Push Your Code to the Space**:
   - Add your Huggingface Space as a remote repository:
     ```sh
     git remote add space https://huggingface.co/spaces/your-username/LLMGuardian
     ```
   - Push your code to the Space:
     ```sh
     git push space main
     ```

3. **Configure the Space**:
   - Ensure that the `app.py` file is in the root directory of your repository.
   - Huggingface will automatically detect and run the `app.py` file.

## Conclusion

Your LLMGuardian application should now be running on Huggingface Spaces with a FastAPI backend and a Gradio frontend. You can access it via the URL provided by Huggingface Spaces.