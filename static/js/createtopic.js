// Tab switching
    document.addEventListener('DOMContentLoaded', function() {
        const textTab = document.getElementById('text-tab');
        const videoTab = document.getElementById('video-tab');
        const textContent = document.getElementById('text-content');
        const videoContent = document.getElementById('video-content');

        textTab.addEventListener('click', function() {
            textTab.classList.add('text-blue-600', 'border-blue-600', 'active');
            textTab.classList.remove('text-gray-500');
            videoTab.classList.remove('text-blue-600', 'border-blue-600', 'active');
            videoTab.classList.add('text-gray-500');
            textContent.classList.remove('hidden');
            videoContent.classList.add('hidden');
        });

        videoTab.addEventListener('click', function() {
            videoTab.classList.add('text-blue-600', 'border-blue-600', 'active');
            videoTab.classList.remove('text-gray-500');
            textTab.classList.remove('text-blue-600', 'border-blue-600', 'active');
            textTab.classList.add('text-gray-500');
            videoContent.classList.remove('hidden');
            textContent.classList.add('hidden');
        });
    });

    // Text formatting functions
    function formatText(command) {
        const textarea = document.getElementById('content_text');
        const start = textarea.selectionStart;
        const end = textarea.selectionEnd;
        const selectedText = textarea.value.substring(start, end);
        
        let formattedText = '';
        switch(command) {
            case 'bold':
                formattedText = `**${selectedText}**`;
                break;
            case 'italic':
                formattedText = `*${selectedText}*`;
                break;
            case 'underline':
                formattedText = `<u>${selectedText}</u>`;
                break;
        }
        
        if (selectedText) {
            textarea.value = textarea.value.substring(0, start) + formattedText + textarea.value.substring(end);
            textarea.selectionStart = start;
            textarea.selectionEnd = start + formattedText.length;
        }
        textarea.focus();
    }

    // Preview functionality
    function previewContent() {
        const title = document.getElementById('title').value;
        const textContent = document.getElementById('content_text').value;
        const videoLink = document.getElementById('video_link').value;
        
        let previewHTML = '';
        if (title) {
            previewHTML += `<h2 class="text-2xl font-bold mb-4">${title}</h2>`;
        }
        
        if (textContent) {
            previewHTML += `<div class="prose max-w-none mb-4">${textContent.replace(/\n/g, '<br>')}</div>`;
        }
        
        if (videoLink) {
            if (videoLink.includes('youtube.com') || videoLink.includes('youtu.be')) {
                const videoId = videoLink.includes('youtu.be') ? 
                    videoLink.split('/').pop() : 
                    videoLink.split('v=')[1]?.split('&')[0];
                if (videoId) {
                    previewHTML += `<div class="mb-4">
                        <iframe width="100%" height="315" src="https://www.youtube.com/embed/${videoId}" 
                            frameborder="0" allowfullscreen class="rounded"></iframe>
                    </div>`;
                }
            } else if (videoLink.includes('vimeo.com')) {
                const videoId = videoLink.split('/').pop();
                previewHTML += `<div class="mb-4">
                    <iframe width="100%" height="315" src="https://player.vimeo.com/video/${videoId}" 
                        frameborder="0" allowfullscreen class="rounded"></iframe>
                </div>`;
            } else {
                previewHTML += `<div class="mb-4">
                    <video width="100%" height="315" controls class="rounded">
                        <source src="${videoLink}" type="video/mp4">
                        Your browser does not support the video tag.
                    </video>
                </div>`;
            }
        }
        
        if (!previewHTML) {
            previewHTML = '<p class="text-gray-500">No content to preview yet.</p>';
        }
        
        document.getElementById('preview-content').innerHTML = previewHTML;
        document.getElementById('preview-modal').classList.remove('hidden');
    }

    function closePreview() {
        document.getElementById('preview-modal').classList.add('hidden');
    }