const form = document.getElementById('override-form');
const RATE_LIMIT = form.dataset.rateLimit;
const VALIDATE_FIELD_PATH = form.dataset.validateFieldPath;
const SUBMIT_REQUEST_PATH = form.dataset.submitRequestPath;
const AUTO_APPROVED_SUCCESS_PATH = form.dataset.autoApprovedSuccessPath;
const REQUEST_SUBMITTED_SUCCESS_PATH = form.dataset.requestSubmittedSuccessPath;

const ERR_REQUIRED = "This field is required.";
const ERR_VALIDATE = "Unable to validate this field due to timeout, please try again.";
const ERR_SUBMIT = "Submission failed, please try again.";
const ERR_TIMEOUT = "Request timed out, please check your connection and try again.";

const SUBMIT_TIMEOUT_MS = 10000;
const FIELDS_SELECTOR = "input, select, textarea";
const FIELD_STATES = {};

const debounce = (callback, delay) => {
    let timerId;
    return (...args) => {
        clearTimeout(timerId);
        timerId = setTimeout(() => callback(...args), delay);
    };
};

const markFieldInvalid = (field, msg) => {
    field.classList.add("invalid");
    field.classList.remove("valid");
    field.closest(".form-field").querySelector(".error-message").textContent = msg;
    FIELD_STATES[field.name] = false;
    updateSubmitButtonState();
};

const markFieldValid = (field) => {
    field.classList.remove("invalid");
    field.classList.add("valid");
    field.closest(".form-field").querySelector(".error-message").textContent = "";
    FIELD_STATES[field.name] = true;
    updateSubmitButtonState();
};

const showBanner = m => {
    const b = document.getElementById("form-error-banner");
    b.textContent = m;
    b.style.display = "block";
};

const hideBanner = () => {
    document.getElementById("form-error-banner").style.display = "none";
};

const updateSubmitButtonState = () => {
    const btn = document.getElementById("submit-button");
    const allValid = Object.values(FIELD_STATES).every(Boolean);
    btn.disabled = !allValid;
    btn.classList.toggle("btn-disabled", !allValid);
};

const validateFieldContents = async (field) => {
    const val = field.type === "checkbox" ? String(field.checked) : field.value.trim();

    if (field.type === "checkbox" && !field.required && !field.checked) {
        markFieldValid(field);
        return;
    }

    if (field.required && ((field.type === "checkbox" && !field.checked) || (field.type !== "checkbox" && !val))) {
        markFieldInvalid(field, ERR_REQUIRED);
        return;
    }

    try {
        const r = await fetch(VALIDATE_FIELD_PATH, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                rateLimit: RATE_LIMIT,
                field: field.name,
                value: val
            })
        });
        const res = await r.json();
        res.valid ? markFieldValid(field) : markFieldInvalid(field, res.error);
    } catch {
        markFieldInvalid(field, ERR_VALIDATE);
    }
};

const submitForm = async (e) => {
    e.preventDefault();
    hideBanner();

    if (!Object.values(FIELD_STATES).every(Boolean)) return;

    const payload = {
        rateLimit: RATE_LIMIT,
        fields: {}
    };
    document.querySelectorAll(FIELDS_SELECTOR).forEach(field => {
        payload.fields[field.name] = field.type === "checkbox" ? String(field.checked) : field.value.trim();
    });

    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), SUBMIT_TIMEOUT_MS);
    try {
        const r = await fetch(SUBMIT_REQUEST_PATH, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
            signal: ctl.signal
        });
        clearTimeout(t);

        if (!r.ok) {
            const d = await r.json().catch(() => ({}));
            showBanner(d.error || ERR_SUBMIT);
            return;
        }
        
        if (r.status === 201) {
            window.location.replace(AUTO_APPROVED_SUCCESS_PATH);
        } else if (r.status === 202) {
            window.location.replace(REQUEST_SUBMITTED_SUCCESS_PATH);
        }
    } catch {
        showBanner(ERR_TIMEOUT);
    }
};

document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("override-form").addEventListener("submit", submitForm);

    document.querySelectorAll(FIELDS_SELECTOR).forEach(field => {
        if (field.tagName === "INPUT" && field.type !== "checkbox") field.setAttribute("autocomplete", "off");
        const isOptionalCheckbox = field.type === "checkbox" && !field.required;
        FIELD_STATES[field.name] = isOptionalCheckbox;
        const handler = () => validateFieldContents(field);
        field.addEventListener(field.type === "checkbox" ? "change" : "input", debounce(handler, 300));
    });
    updateSubmitButtonState();
});
