'use strict';

(() => {
  // -- Base64URL utilities --

  function base64UrlEncode(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  function base64UrlDecode(base64url) {
    const padLength = (4 - (base64url.length % 4)) % 4;
    const base64 = base64url
      .replace(/-/g, '+')
      .replace(/_/g, '/')
      .padEnd(base64url.length + padLength, '=');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  // -- Helpers --

  function getMeta(name) {
    return document.querySelector(`meta[name="${name}"]`)?.content ?? '';
  }

  function csrfHeaders(json = true) {
    const headers = { [getMeta('csrf-header')]: getMeta('csrf-token') };
    if (json) {
      headers['Content-Type'] = 'application/json';
    }
    return headers;
  }

  function showMessage(elementId, message, isError) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.textContent = message;
    el.style.display = 'block';
    el.classList.remove('error', 'success', 'alert-error', 'alert-success');
    el.classList.add(isError ? 'error' : 'success');
  }

  function decodeCredentialIds(credentials) {
    return credentials.map((cred) => ({ ...cred, id: base64UrlDecode(cred.id) }));
  }

  // -- Passkey credential creation (shared) --

  async function createAndSubmitPasskey(label) {
    const response = await fetch('/webauthn/register/options', {
      method: 'POST',
      headers: csrfHeaders(),
    });

    if (!response.ok) {
      throw new Error(`Failed to get registration options (HTTP ${response.status})`);
    }

    const options = await response.json();

    options.challenge = base64UrlDecode(options.challenge);
    options.user.id = base64UrlDecode(options.user.id);
    if (options.excludeCredentials) {
      options.excludeCredentials = decodeCredentialIds(options.excludeCredentials);
    }

    const credential = await navigator.credentials.create({ publicKey: options });

    const body = {
      publicKey: {
        credential: {
          id: credential.id,
          rawId: base64UrlEncode(credential.rawId),
          response: {
            attestationObject: base64UrlEncode(credential.response.attestationObject),
            clientDataJSON: base64UrlEncode(credential.response.clientDataJSON),
            ...(credential.response.getTransports && {
              transports: credential.response.getTransports(),
            }),
          },
          type: credential.type,
          clientExtensionResults: credential.getClientExtensionResults(),
          authenticatorAttachment: credential.authenticatorAttachment ?? '',
        },
        label,
      },
    };

    const registerRes = await fetch('/webauthn/register', {
      method: 'POST',
      headers: csrfHeaders(),
      body: JSON.stringify(body),
    });

    if (!registerRes.ok) {
      const errBody = await registerRes.text();
      throw new Error(`Registration failed: ${errBody}`);
    }
  }

  // -- Passkey registration (portal page) --

  async function registerPasskey() {
    const labelInput = document.getElementById('passkey-label');
    const label = labelInput?.value.trim() || 'My Passkey';

    try {
      await createAndSubmitPasskey(label);
      showMessage('passkey-message', 'Passkey registered successfully!', false);
      setTimeout(() => window.location.reload(), 1000);
    } catch (err) {
      const message = err.name === 'NotAllowedError'
        ? 'Passkey registration was cancelled.'
        : `Error: ${err.message}`;
      showMessage('passkey-message', message, true);
    }
  }

  // -- Passkey registration during signup (register page) --

  async function registerWithPasskey() {
    const emailInput = document.getElementById('email');
    if (!emailInput || !emailInput.value.trim()) {
      showMessage('passkey-error', 'Please enter your email address.', true);
      return;
    }

    const email = emailInput.value.trim();
    const btn = document.getElementById('choosePasskey');
    if (btn) btn.disabled = true;

    try {
      // Step 1: Create account and establish session
      const startRes = await fetch('/register/passkey/start', {
        method: 'POST',
        headers: csrfHeaders(),
        body: JSON.stringify({ email }),
      });

      if (!startRes.ok) {
        const errBody = await startRes.json();
        throw new Error(errBody.error || 'Failed to start registration');
      }

      // Step 2: Run WebAuthn ceremony
      try {
        await createAndSubmitPasskey('My Passkey');
      } catch (err) {
        // WebAuthn failed or was cancelled — roll back the account
        await fetch('/register/passkey/cancel', {
          method: 'POST',
          headers: csrfHeaders(),
        });
        throw err;
      }

      // Step 3: Success — redirect to portal
      window.location.href = '/portal';
    } catch (err) {
      if (btn) btn.disabled = false;
      const message = err.name === 'NotAllowedError'
        ? 'Passkey registration was cancelled. No account was created.'
        : `Error: ${err.message}`;
      showMessage('passkey-error', message, true);
    }
  }

  // -- Passkey authentication (login page) --

  async function loginWithPasskey() {
    try {
      const response = await fetch('/webauthn/authenticate/options', {
        method: 'POST',
        headers: csrfHeaders(),
      });

      if (!response.ok) {
        throw new Error(`Failed to get authentication options (HTTP ${response.status})`);
      }

      const options = await response.json();

      options.challenge = base64UrlDecode(options.challenge);
      if (options.allowCredentials) {
        options.allowCredentials = decodeCredentialIds(options.allowCredentials);
      }

      const assertion = await navigator.credentials.get({ publicKey: options });

      const body = {
        id: assertion.id,
        rawId: base64UrlEncode(assertion.rawId),
        response: {
          authenticatorData: base64UrlEncode(assertion.response.authenticatorData),
          clientDataJSON: base64UrlEncode(assertion.response.clientDataJSON),
          signature: base64UrlEncode(assertion.response.signature),
          ...(assertion.response.userHandle && {
            userHandle: base64UrlEncode(assertion.response.userHandle),
          }),
        },
        credType: assertion.type,
        clientExtensionResults: assertion.getClientExtensionResults(),
        authenticatorAttachment: assertion.authenticatorAttachment,
      };

      const loginRes = await fetch('/login/webauthn', {
        method: 'POST',
        headers: csrfHeaders(),
        body: JSON.stringify(body),
      });

      if (!loginRes.ok) {
        let errMsg = `Authentication failed (HTTP ${loginRes.status})`;
        try {
          const errBody = await loginRes.json();
          if (errBody.error) errMsg = errBody.error;
        } catch {
          // no JSON body
        }
        throw new Error(errMsg);
      }

      const result = await loginRes.json();
      window.location.href = result.redirectUrl || '/portal';
    } catch (err) {
      const message = err.name === 'NotAllowedError'
        ? 'Passkey authentication was cancelled.'
        : `Error: ${err.message}`;
      showMessage('passkey-error', message, true);
    }
  }

  // -- Passkey deletion (portal page) --

  async function deletePasskey(credentialId) {
    if (!confirm('Remove this passkey?')) return;

    try {
      const response = await fetch(`/webauthn/register/${encodeURIComponent(credentialId)}`, {
        method: 'DELETE',
        headers: csrfHeaders(false),
      });

      if (!response.ok) {
        throw new Error('Failed to remove passkey.');
      }

      window.location.reload();
    } catch (err) {
      showMessage('passkey-message', `Error: ${err.message}`, true);
    }
  }

  // -- UI state transitions --

  function showEmailLoginForm() {
    document.getElementById('choiceButtons').style.display = 'none';
    document.getElementById('backLink').style.display = 'block';
    const form = document.getElementById('emailPasswordForm');
    form.style.display = 'block';
    const emailInput = document.getElementById('username');
    emailInput.required = true;
    document.getElementById('password').required = true;
    emailInput.focus();
  }

  function showChoiceButtons() {
    document.getElementById('emailPasswordForm').style.display = 'none';
    document.getElementById('backLink').style.display = 'none';
    document.getElementById('username').required = false;
    document.getElementById('password').required = false;
    document.getElementById('choiceButtons').style.display = '';
  }

  function showPasswordFields() {
    document.getElementById('choiceButtons').style.display = 'none';
    const passwordInput = document.getElementById('password');
    document.getElementById('passwordFields').classList.add('visible');
    passwordInput.required = true;
    document.getElementById('confirmPassword').required = true;
    passwordInput.focus();
  }

  // -- Event binding --

  const actions = {
    'register-passkey': () => registerPasskey(),
    'register-with-passkey': () => registerWithPasskey(),
    'login-passkey': () => loginWithPasskey(),
    'delete-passkey': (_e, target) => deletePasskey(target.dataset.credentialId),
    'back-to-choices': () => showChoiceButtons(),
    'choose-email-login': () => showEmailLoginForm(),
    'choose-password': () => showPasswordFields(),
  };

  document.addEventListener('DOMContentLoaded', () => {
    // If email/password form is already visible (e.g. after login error), enable required fields
    const loginForm = document.getElementById('emailPasswordForm');
    if (loginForm && loginForm.style.display !== 'none') {
      const emailField = document.getElementById('username');
      if (emailField) { emailField.required = true; emailField.focus(); }
      const pwField = document.getElementById('password');
      if (pwField) pwField.required = true;
    }

    document.addEventListener('click', (e) => {
      const target = e.target.closest('[data-action]');
      if (!target) return;

      const handler = actions[target.dataset.action];
      if (handler) handler(e, target);
    });
  });
})();
