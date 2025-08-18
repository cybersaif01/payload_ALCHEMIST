document.getElementById('scan-form').addEventListener('submit', function(e){
    e.preventDefault();
    const domain = document.getElementById('domain').value;
    const output = document.getElementById('output');
    output.innerHTML = '<div class="log-entry info">🚀 Starting scan...</div>';

    fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain, mode: 'full', save_report: false })
    })
    .then(response => response.json())
    .then(data => {
        if (data.output) {
            output.innerHTML += `<div class="log-entry">${data.output.replace(/\n/g, '<br>')}</div>`;
        }
        if (data.error) {
            output.innerHTML += `<div class="log-entry error">${data.error.replace(/\n/g, '<br>')}</div>`;
        }
    })
    .catch(err => {
        output.innerHTML += `<div class="log-entry error">❌ Error: ${err}</div>`;
    });
});
