
import { Editor } from 'https://esm.sh/@tiptap/core@2.1.13'
import StarterKit from 'https://esm.sh/@tiptap/starter-kit@2.1.13'
import Placeholder from 'https://esm.sh/@tiptap/extension-placeholder@2.1.13'

// Get elements
const urlDisplay = document.getElementById('urlDisplay');
const copyBtn = document.getElementById('copyBtn');
const status = document.getElementById('status');
const passwordToggle = document.getElementById('passwordToggle');
const passwordGroup = document.getElementById('passwordGroup');
const passwordInput = document.getElementById('passwordInput');
const encryptionStatus = document.getElementById('encryptionStatus');
const passwordModal = document.getElementById('passwordModal');
const modalPasswordInput = document.getElementById('modalPasswordInput');
const modalUnlockBtn = document.getElementById('modalUnlockBtn');
const modalCancelBtn = document.getElementById('modalCancelBtn');

let isPasswordEnabled = false;
let currentEncryptedData = null;
let editor = null;

// Enhanced compression with encryption prefix
const ENCRYPTED_PREFIX = 'ENC:';

// Debounce function for performance
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Initialize Tiptap Editor
function initEditor() {
    editor = new Editor({
        element: document.getElementById('noteText'),
        extensions: [
            StarterKit,
            Placeholder.configure({
                placeholder: `Type your note (markdown supported)`
            })
        ],
        content: '',
        onUpdate: ({ editor }) => {
            debouncedUpdateUrl();
        },
        editorProps: {
            attributes: {
                class: 'prose prose-sm max-w-none',
            },
            handlePaste: (view, event, slice) => {
                // Get the pasted text
                const pastedText = event.clipboardData?.getData('text/plain');

                if (pastedText) {
                    // Check if the pasted text looks like markdown
                    const hasMarkdownPatterns = /^#{1,6}\s+|^\*\*(.*?)\*\*|\*(.*?)\*|`([^`]+)`|^>\s+|^[-*]\s+|^\d+\.\s+|```/m.test(pastedText);

                    if (hasMarkdownPatterns) {
                        // Convert markdown to HTML and replace content
                        event.preventDefault();
                        const html = markdownToHtml(pastedText);

                        // Get current content and cursor position
                        const { from, to } = view.state.selection;
                        const currentHTML = editor.getHTML();

                        // If we're replacing selected text or at end, just insert
                        if (from === to && from === view.state.doc.content.size - 1) {
                            // At end of document, append
                            editor.commands.insertContent(html);
                        } else {
                            // Replace selection with converted markdown
                            editor.chain().focus().deleteSelection().insertContent(html).run();
                        }

                        return true; // Prevent default paste
                    }
                }

                return false; // Allow default paste for non-markdown content
            }
        },
    });
}

// Helper function to convert HTML to Markdown-ish text
function htmlToMarkdown(html) {
    const temp = document.createElement('div');
    temp.innerHTML = html;

    let text = '';

    function processNode(node) {
        if (node.nodeType === Node.TEXT_NODE) {
            text += node.textContent;
        } else if (node.nodeType === Node.ELEMENT_NODE) {
            switch (node.tagName.toLowerCase()) {
                case 'h1':
                    text += '# ' + node.textContent + '\n\n';
                    break;
                case 'h2':
                    text += '## ' + node.textContent + '\n\n';
                    break;
                case 'h3':
                    text += '### ' + node.textContent + '\n\n';
                    break;
                case 'h4':
                    text += '#### ' + node.textContent + '\n\n';
                    break;
                case 'h5':
                    text += '##### ' + node.textContent + '\n\n';
                    break;
                case 'h6':
                    text += '###### ' + node.textContent + '\n\n';
                    break;
                case 'p':
                    if (node.textContent.trim() === '') {
                        // Empty paragraph - preserve as empty line
                        text += '\n';
                    } else {
                        // Process children first to handle inline formatting
                        Array.from(node.childNodes).forEach(processNode);
                        text += '\n\n';
                    }
                    break;
                case 'strong':
                case 'b':
                    text += '**' + node.textContent + '**';
                    break;
                case 'em':
                case 'i':
                    text += '*' + node.textContent + '*';
                    break;
                case 'code':
                    if (node.parentNode.tagName.toLowerCase() !== 'pre') {
                        text += '`' + node.textContent + '`';
                    } else {
                        text += node.textContent;
                    }
                    break;
                case 'pre':
                    text += '```\n' + node.textContent + '\n```\n\n';
                    break;
                case 'blockquote':
                    text += '> ' + node.textContent.replace(/\n/g, '\n> ') + '\n\n';
                    break;
                case 'ul':
                    Array.from(node.children).forEach(li => {
                        text += '- ' + li.textContent + '\n';
                    });
                    text += '\n';
                    break;
                case 'ol':
                    Array.from(node.children).forEach((li, index) => {
                        text += (index + 1) + '. ' + li.textContent + '\n';
                    });
                    text += '\n';
                    break;
                case 'br':
                    text += '  \n'; // Two spaces + newline for markdown line break
                    break;
                case 'hr':
                    text += '---\n\n';
                    break;
                case 'a':
                    text += '[' + node.textContent + '](' + node.href + ')';
                    break;
                default:
                    // For other elements, process children
                    Array.from(node.childNodes).forEach(processNode);
            }
        }
    }

    Array.from(temp.childNodes).forEach(processNode);

    // Clean up extra newlines but preserve intentional line breaks
    return text.replace(/\n\n\n+/g, '\n\n').trim();
}

// Helper function to convert markdown text back to HTML
function markdownToHtml(markdown) {
    if (!markdown || markdown.trim() === '') {
        return '<p></p>';
    }

    let html = '';
    const lines = markdown.split('\n');
    let i = 0;

    while (i < lines.length) {
        const line = lines[i];
        const trimmedLine = line.trim();

        if (line.match(/^#{1,6}\s+/)) {
            // Match headers (1-6 hashes followed by space)
            const level = line.match(/^#+/)[0].length;
            const content = line.slice(level + 1); // +1 for the space after hashes
            html += `<h${level}>${content}</h${level}>`;
            i++;
        } else if (line.startsWith('> ')) {
            html += `<blockquote>${line.slice(2)}</blockquote>`;
            i++;
        } else if (line.startsWith('- ')) {
            html += '<ul>';
            while (i < lines.length && lines[i].startsWith('- ')) {
                html += `<li>${lines[i].slice(2)}</li>`;
                i++;
            }
            html += '</ul>';
        } else if (line.match(/^\d+\. /)) {
            html += '<ol>';
            while (i < lines.length && lines[i].match(/^\d+\. /)) {
                html += `<li>${lines[i].replace(/^\d+\. /, '')}</li>`;
                i++;
            }
            html += '</ol>';
        } else if (line.startsWith('```')) {
            html += '<pre><code>';
            i++;
            while (i < lines.length && !lines[i].startsWith('```')) {
                html += lines[i] + '\n';
                i++;
            }
            html += '</code></pre>';
            i++; // Skip closing ```
        } else if (trimmedLine === '') {
            // Only add empty paragraph if we have content before and after
            if (i > 0 && i < lines.length - 1 &&
                lines[i - 1].trim() !== '' && lines[i + 1].trim() !== '') {
                html += '<p></p>';
            }
            i++;
        } else {
            // Regular paragraph - process inline formatting and line breaks
            let paragraphContent = line;

            // Handle markdown line breaks (two spaces at end of line)
            if (paragraphContent.endsWith('  ')) {
                paragraphContent = paragraphContent.slice(0, -2) + '<br>';
            }

            // Handle inline formatting
            paragraphContent = paragraphContent
                .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                .replace(/\*(.*?)\*/g, '<em>$1</em>')
                .replace(/`([^`]+)`/g, '<code>$1</code>')
                .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');

            html += `<p>${paragraphContent}</p>`;
            i++;
        }
    }

    return html || '<p></p>';
}

// Crypto functions
async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );

    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptNote(note, password) {
    if (!password) return note;

    try {
        const encoder = new TextEncoder();
        const data = encoder.encode(note);
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));

        const key = await deriveKey(password, salt);
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            data
        );

        const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
        combined.set(salt, 0);
        combined.set(iv, salt.length);
        combined.set(new Uint8Array(encrypted), salt.length + iv.length);

        const base64 = btoa(String.fromCharCode(...combined));
        return ENCRYPTED_PREFIX + base64;
    } catch (error) {
        console.error('Encryption error:', error);
        throw new Error('Failed to encrypt note');
    }
}

async function decryptNote(encryptedNote, password) {
    if (!encryptedNote.startsWith(ENCRYPTED_PREFIX)) {
        return encryptedNote;
    }

    try {
        const base64Data = encryptedNote.substring(ENCRYPTED_PREFIX.length);
        const combined = new Uint8Array(atob(base64Data).split('').map(c => c.charCodeAt(0)));

        const salt = combined.slice(0, 16);
        const iv = combined.slice(16, 28);
        const encrypted = combined.slice(28);

        const key = await deriveKey(password, salt);
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            encrypted
        );

        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    } catch (error) {
        console.error('Decryption error:', error);
        throw new Error('Failed to decrypt note - incorrect password?');
    }
}

function isEncrypted(data) {
    return data && data.startsWith(ENCRYPTED_PREFIX);
}

async function encodeNote(note) {
    try {
        let processedNote = note;

        if (isPasswordEnabled && passwordInput.value) {
            processedNote = await encryptNote(note, passwordInput.value);
        }

        return LZString.compressToEncodedURIComponent(processedNote);
    } catch (error) {
        showStatus('Encryption failed: ' + error.message, 'error');
        return LZString.compressToEncodedURIComponent(note);
    }
}

async function decodeNote(encodedNote, password = null) {
    try {
        const decompressed = LZString.decompressFromEncodedURIComponent(encodedNote);

        if (isEncrypted(decompressed)) {
            if (!password) {
                currentEncryptedData = decompressed;
                return null;
            }
            return await decryptNote(decompressed, password);
        }

        return decompressed;
    } catch (error) {
        console.error('Error decoding note:', error);
        throw error;
    }
}

function updateEncryptionStatus() {
    if (isPasswordEnabled && passwordInput.value) {
        encryptionStatus.textContent = 'Encrypted';
    } else {
        encryptionStatus.textContent = 'Not encrypted';
    }
}

async function loadNoteFromUrl() {
    const hash = window.location.hash.substring(1);
    if (hash) {
        try {
            const decodedNote = await decodeNote(hash);
            if (decodedNote === null) {
                showPasswordModal();
                return;
            }

            // Set content in editor using improved markdown conversion
            if (editor) {
                const html = markdownToHtml(decodedNote);
                editor.commands.setContent(html);
            }

            updateUrlDisplay();
        } catch (e) {
            console.error('Error decoding note from URL:', e);
            showStatus('Error loading note from URL', 'error');
        }
    }
}

async function updateUrl() {
    if (!editor) return;

    // Get markdown-like content from editor
    const htmlContent = editor.getHTML();
    const markdownContent = htmlToMarkdown(htmlContent);

    if (markdownContent.trim()) {
        const encodedNote = await encodeNote(markdownContent);
        window.history.replaceState(null, null, `#${encodedNote}`);
    } else {
        window.history.replaceState(null, null, window.location.pathname);
    }
    updateUrlDisplay();
}

function updateUrlDisplay() {
    const currentUrl = window.location.href;
    urlDisplay.textContent = currentUrl;
}

async function copyToClipboard() {
    try {
        await navigator.clipboard.writeText(window.location.href);
        showStatus('URL copied to clipboard', 'success');
    } catch (err) {
        const textArea = document.createElement('textarea');
        textArea.value = window.location.href;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        showStatus('URL copied to clipboard', 'success');
    }
}

function showStatus(message, type) {
    status.textContent = message;
    status.className = `status ${type}`;
    setTimeout(() => {
        status.style.opacity = '0';
        setTimeout(() => {
            status.className = 'status';
        }, 300);
    }, 3000);
}

function showPasswordModal() {
    passwordModal.classList.add('show');
    modalPasswordInput.focus();
}

function hidePasswordModal() {
    passwordModal.classList.remove('show');
    modalPasswordInput.value = '';
}

async function unlockWithPassword() {
    const password = modalPasswordInput.value;
    if (!password) {
        showStatus('Please enter a password', 'error');
        return;
    }

    try {
        const decryptedNote = await decryptNote(currentEncryptedData, password);

        if (editor) {
            const html = markdownToHtml(decryptedNote);
            editor.commands.setContent(html);
        }

        updateUrlDisplay();
        hidePasswordModal();
        showStatus('Note unlocked successfully', 'success');
    } catch (error) {
        showStatus('Incorrect password', 'error');
        modalPasswordInput.value = '';
        modalPasswordInput.focus();
    }
}

// Debounced functions
const debouncedUpdateUrl = debounce(updateUrl, 300);

// Event listeners
copyBtn.addEventListener('click', copyToClipboard);

passwordToggle.addEventListener('click', () => {
    isPasswordEnabled = !isPasswordEnabled;
    passwordToggle.classList.toggle('active', isPasswordEnabled);
    passwordGroup.classList.toggle('show', isPasswordEnabled);

    if (isPasswordEnabled) {
        passwordInput.focus();
    } else {
        passwordInput.value = '';
    }

    updateEncryptionStatus();
    debouncedUpdateUrl();
});

passwordInput.addEventListener('input', () => {
    updateEncryptionStatus();
    debouncedUpdateUrl();
});

modalUnlockBtn.addEventListener('click', unlockWithPassword);
modalCancelBtn.addEventListener('click', hidePasswordModal);

modalPasswordInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        unlockWithPassword();
    }
});

passwordModal.addEventListener('click', (e) => {
    if (e.target === passwordModal) {
        hidePasswordModal();
    }
});

// Initialize everything
initEditor();
setTimeout(() => {
    loadNoteFromUrl();
    updateUrlDisplay();
    updateEncryptionStatus();
}, 100);
