# Command Line Interface

**cli_interface.py**

1. **Provides Core Commands**:
   - `scan`: Scan individual prompts
   - `batch-scan`: Process multiple prompts from a file
   - `add-pattern`: Add new detection patterns
   - `list-patterns`: View active patterns
   - `configure`: Adjust settings
   - `version`: Show version info

2. **Features**:
   - Rich terminal output with tables and formatting
   - JSON output option for automation
   - Configuration management
   - Batch processing capability
   - Detailed error handling
   - Logging support

3. **User Experience**:
   - Clear, colorful output
   - Progress indicators for long operations
   - Detailed help messages
   - Input validation
   - Configuration persistence

To use the CLI:

```bash
# Install dependencies
pip install -r requirements.txt

# Basic prompt scan
llmguardian scan "Your prompt here"

# Scan with context
llmguardian scan "Your prompt" --context "Previous conversation"

# Batch scanning
llmguardian batch-scan input.txt results.json

# Add new pattern
llmguardian add-pattern -p "pattern" -t direct -s 8 -d "description"

# Configure settings
llmguardian configure --risk-threshold 8 --confidence-threshold 0.8
```
