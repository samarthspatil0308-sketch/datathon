const REDACTED = "[REDACTED]";

/**
 * Scan and redact sensitive information
 */
function scanDocument(text, customPhrases = []) {
    if (!text || typeof text !== "string") {
        throw new Error("Invalid input");
    }

    let sanitizedText = text;

    const categories = [];
    const counts = {
        emails: 0,
        phones: 0,
        structuredFields: 0,
        customPhrases: 0
    };

    // Email Detection
    const emailRegex =
        /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

    const emailMatches = sanitizedText.match(emailRegex) || [];

    if (emailMatches.length > 0) {
        counts.emails = emailMatches.length;
        categories.push("EMAIL");
        sanitizedText = sanitizedText.replace(emailRegex, REDACTED);
    }

    // Phone Detection
    const phoneRegex =
        /(?:\+91[\s-]?)?[6-9]\d{9}|\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g;

    const phoneMatches = sanitizedText.match(phoneRegex) || [];

    if (phoneMatches.length > 0) {
        counts.phones = phoneMatches.length;
        categories.push("PHONE");
        sanitizedText = sanitizedText.replace(phoneRegex, REDACTED);
    }

    // Structured Fields
    const fieldPatterns = [
        /(Name\s*:\s*)(.+)/gi,
        /(Address\s*:\s*)(.+)/gi,
        /(Email\s*:\s*)(.+)/gi,
        /(Account Number\s*:\s*)(.+)/gi
    ];

    fieldPatterns.forEach(pattern => {
        sanitizedText = sanitizedText.replace(
            pattern,
            (match, label) => {
                counts.structuredFields++;

                if (!categories.includes("STRUCTURED_FIELD")) {
                    categories.push("STRUCTURED_FIELD");
                }

                return label + REDACTED;
            }
        );
    });

    // Custom Confidential Phrases
    customPhrases.forEach(phrase => {

        if (!phrase) return;

        const regex = new RegExp(
            phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
            "gi"
        );

        const found = sanitizedText.match(regex);

        if (found) {
            counts.customPhrases += found.length;

            if (!categories.includes("CUSTOM_PHRASE")) {
                categories.push("CUSTOM_PHRASE");
            }

            sanitizedText = sanitizedText.replace(
                regex,
                REDACTED
            );
        }
    });

    return {
        sanitizedText,
        categories,
        counts
    };
}

/**
 * Validate sanitized data before AI request
 */
function validatePrivacy(result) {

    const emailRegex =
        /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/;

    const phoneRegex =
        /(?:\+91[\s-]?)?[6-9]\d{9}/;

    if (emailRegex.test(result.sanitizedText)) {
        return {
            valid: false,
            reason: "Email still found"
        };
    }

    if (phoneRegex.test(result.sanitizedText)) {
        return {
            valid: false,
            reason: "Phone number still found"
        };
    }

    return {
        valid: true
    };
}

/**
 * Main function called before AI processing
 */
function processForAI(text, phrases = []) {

    const result = scanDocument(text, phrases);

    const validation = validatePrivacy(result);

    if (!validation.valid) {

        throw new Error(
            "Privacy validation failed. AI processing blocked."
        );
    }

    return result;
}