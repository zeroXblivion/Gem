# Gem - AI-Powered Function and Label Renaming for IDA Pro

Tired of staring at `sub_401000` and `loc_12345` while reverse engineering? Gem hooks up Google's Gemini AI to IDA Pro and gives your functions and labels actual meaningful names. Just point it at some code, and it'll figure out what's going on and suggest proper names based on the context.

## Configuration

1. Open `gem.py` in a text editor
2. Replace `YOUR_GEMINI_API_KEY_HERE` with your Gemini API key:
    
    ```python
    if not self.api_key or self.api_key == "your_actual_api_key_here"
    ```
    
3. Save the file

### Getting a Gemini API Key

1. Visit https://ai.google.dev/gemini-api/docs/api-key
2. Create a new API key
3. Copy and paste into the plugin configuration

## Video Tutorial

See the included video demonstration for detailed usage examples.

https://github.com/user-attachments/assets/51a4b935-2341-4f68-a337-2b0d028318aa

## Privacy and Security

- Code snippets are sent to Google's Gemini API for analysis
- Only function/label context is transmitted, not entire binaries
- Don't be paranoid :D
