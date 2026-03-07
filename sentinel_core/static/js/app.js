// Sentinel Core - Elite JavaScript Application

// Sidebar Toggle
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.getElementById('mainContent');
    sidebar.classList.toggle('collapsed');
    mainContent.classList.toggle('expanded');
}

function toggleMobileMenu() {
    const sidebar = document.getElementById('sidebar');
    sidebar.classList.toggle('mobile-open');
}

// User Menu Toggle
function toggleUserMenu() {
    // Could expand to show dropdown menu
    console.log('User menu clicked');
}

// AI Modal Functions
function openAIModal() {
    document.getElementById('aiModal').classList.add('active');
}

function closeAIModal() {
    document.getElementById('aiModal').classList.remove('active');
}

async function sendAIMessage() {
    const input = document.getElementById('aiInput');
    const role = document.getElementById('aiRole').value;
    const messagesContainer = document.getElementById('aiMessages');
    
    const message = input.value.trim();
    if (!message) return;
    
    // Add user message
    messagesContainer.innerHTML += `
        <div class="ai-message user">
            <div class="ai-message-content">${escapeHtml(message)}</div>
        </div>
    `;
    
    input.value = '';
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
    
    // Show loading
    const loadingId = 'loading-' + Date.now();
    messagesContainer.innerHTML += `
        <div class="ai-message" id="${loadingId}">
            <div class="ai-message-content"><i class="fas fa-spinner spin"></i> Thinking...</div>
        </div>
    `;
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
    
    try {
        const response = await fetch('/ai/analyze', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({prompt: message, role: role})
        });
        
        const data = await response.json();
        
        // Remove loading
        document.getElementById(loadingId).remove();
        
        if (data.success) {
            messagesContainer.innerHTML += `
                <div class="ai-message">
                    <div class="ai-message-content">${formatAIResponse(data.response)}</div>
                </div>
            `;
        } else {
            messagesContainer.innerHTML += `
                <div class="ai-message" style="border-left-color: var(--error);">
                    <div class="ai-message-content">Error: ${escapeHtml(data.error || 'Unknown error')}</div>
                </div>
            `;
        }
    } catch (e) {
        document.getElementById(loadingId).remove();
        messagesContainer.innerHTML += `
            <div class="ai-message" style="border-left-color: var(--error);">
                <div class="ai-message-content">Error: ${e.message}</div>
            </div>
        `;
    }
    
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

// Utility Functions
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatAIResponse(text) {
    // Convert markdown-style formatting to HTML
    return escapeHtml(text)
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.*?)\*/g, '<em>$1</em>')
        .replace(/`(.*?)`/g, '<code style="background: var(--bg-primary); padding: 2px 6px; border-radius: 4px;">$1</code>')
        .replace(/\n/g, '<br>');
}

// Toast Notifications Auto-dismiss
document.addEventListener('DOMContentLoaded', () => {
    const toasts = document.querySelectorAll('.toast');
    toasts.forEach(toast => {
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            setTimeout(() => toast.remove(), 300);
        }, 5000);
    });
});

// Keyboard Shortcuts
document.addEventListener('keydown', (e) => {
    // Ctrl+K to open AI assistant
    if (e.ctrlKey && e.key === 'k') {
        e.preventDefault();
        openAIModal();
    }
    // Escape to close modals
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal-overlay.active').forEach(modal => {
            modal.classList.remove('active');
        });
    }
});

// Auto-save form data to localStorage
document.querySelectorAll('form').forEach(form => {
    form.addEventListener('input', (e) => {
        if (e.target.name) {
            localStorage.setItem('form_' + e.target.name, e.target.value);
        }
    });
});

// Confirm before leaving with unsaved changes
let formChanged = false;
document.querySelectorAll('form').forEach(form => {
    form.addEventListener('change', () => formChanged = true);
    form.addEventListener('submit', () => formChanged = false);
});

window.addEventListener('beforeunload', (e) => {
    if (formChanged) {
        e.preventDefault();
        e.returnValue = '';
    }
});

console.log('Sentinel Core initialized 🛡️');
