async def gemini_explain(input_text, label, flags):
    if not GEMINI_API_KEY:
        clean = humanize_flags(flags[:2])
        return "This URL appears to be a phishing attempt because " + " and ".join(clean) + "."

    try:
        client = genai.Client(api_key=GEMINI_API_KEY)

        prompt = (
            f"You are a cybersecurity expert.\n"
            f"This URL is classified as {label}.\n\n"
            f"Input: {input_text}\n\n"
            f"Behaviors: {', '.join(humanize_flags(flags[:3]))}\n\n"
            f"Explain in 2 short sentences why this is {label.lower()}.\n"
            f"No bullet points. Write in one paragraph."
        )

        response = client.models.generate_content(
            model="gemini-1.5-flash",
            contents=prompt
        )

        text = response.text.replace("\n", " ").replace("•", "").replace("- ", "")
        return text.strip()

    except Exception as e:
        print("GEMINI ERROR:", e)
        return f"Classified as {label} based on detected patterns."
