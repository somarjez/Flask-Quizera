  // Search functionality
        function setupSearch(searchInputId, containerId, itemSelector, searchFields) {
            const searchInput = document.getElementById(searchInputId);
            const container = document.getElementById(containerId);
            
            if (searchInput && container) {
                searchInput.addEventListener('input', function() {
                    const searchTerm = this.value.toLowerCase();
                    const items = container.querySelectorAll(itemSelector);
                    
                    items.forEach(item => {
                        let shouldShow = false;
                        
                        searchFields.forEach(field => {
                            const fieldValue = item.dataset[field] || '';
                            if (fieldValue.includes(searchTerm)) {
                                shouldShow = true;
                            }
                        });
                        
                        if (shouldShow || searchTerm === '') {
                            item.style.display = 'block';
                        } else {
                            item.style.display = 'none';
                        }
                    });
                    
                    // For grouped quizzes, hide empty subject groups
                    if (containerId.includes('quiz')) {
                        const subjectGroups = container.querySelectorAll('.subject-group');
                        subjectGroups.forEach(group => {
                            const visibleQuizzes = group.querySelectorAll('.quiz-card:not([style*="display: none"])');
                            if (visibleQuizzes.length === 0 && searchTerm !== '') {
                                group.style.display = 'none';
                            } else {
                                group.style.display = 'block';
                            }
                        });
                    }
                });
            }
        }
        
        // Subject filter functionality
        function setupSubjectFilter(filterId, containerId) {
            const filter = document.getElementById(filterId);
            const container = document.getElementById(containerId);
            
            if (filter && container) {
                filter.addEventListener('change', function() {
                    const selectedSubject = this.value.toLowerCase();
                    const subjectGroups = container.querySelectorAll('.subject-group');
                    
                    subjectGroups.forEach(group => {
                        if (selectedSubject === '' || group.dataset.subject === selectedSubject) {
                            group.style.display = 'block';
                        } else {
                            group.style.display = 'none';
                        }
                    });
                });
            }
        }
        
        // Generate unique certificate ID
        function generateCertificateId() {
            const timestamp = Date.now().toString(36);
            const random = Math.random().toString(36).substr(2, 5);
            return (timestamp + random).toUpperCase();
        }
        
        // Enhanced Certificate functions
        function generateCertificate(subjectId, subjectName) {
            const currentDate = new Date().toLocaleDateString('en-US', { 
                year: 'numeric', 
                month: 'long', 
                day: 'numeric' 
            });
            
            const certificateId = generateCertificateId();
            
            // Update certificate content
            document.getElementById('subjectName').textContent = subjectName;
            document.getElementById('completionDate').textContent = currentDate;
            document.getElementById('certificateId').textContent = certificateId;
            
            // Show modal
            document.getElementById('certificateModal').classList.remove('hidden');
        }
        
        function closeCertificateModal() {
            document.getElementById('certificateModal').classList.add('hidden');
        }
        
        // Enhanced PDF download function for landscape
        async function downloadCertificateAsPDF() {
            try {
                const { jsPDF } = window.jspdf;
                const certificate = document.getElementById('certificatePreview');
                
                // Temporarily scale up for better quality
                certificate.style.transform = 'scale(1)';
                
                // Use html2canvas to capture the certificate
                const canvas = await html2canvas(certificate, {
                    scale: 2,
                    useCORS: true,
                    backgroundColor: '#ffffff',
                    width: 1123, // A4 landscape width in pixels at 96 DPI
                    height: 794   // A4 landscape height in pixels at 96 DPI
                });
                
                // Create PDF in landscape orientation
                const pdf = new jsPDF({
                    orientation: 'landscape',
                    unit: 'mm',
                    format: 'a4'
                });
                
                const imgData = canvas.toDataURL('image/png');
                pdf.addImage(imgData, 'PNG', 0, 0, 297, 210); // A4 landscape dimensions in mm
                
                // Generate filename
                const subjectName = document.getElementById('subjectName').textContent;
                const studentName = document.getElementById('studentName').textContent;
                const certificateId = document.getElementById('certificateId').textContent;
                const filename = `Certificate_${studentName}_${subjectName}_${certificateId}.pdf`.replace(/[^a-zA-Z0-9_-]/g, '_');
                
                // Download PDF
                pdf.save(filename);
                
                // Reset scale
                certificate.style.transform = 'scale(0.5)';
                
            } catch (error) {
                console.error('Error generating PDF:', error);
                alert('Error generating PDF. Please try again or use the print option.');
            }
        }
        
        // Print function for landscape
        function printCertificate() {
            const printWindow = window.open('', '', 'height=794,width=1123');
            const certificateHTML = document.getElementById('certificatePreview').outerHTML;
            
            printWindow.document.write(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Certificate of Completion</title>
                    <style>
                        @page {
                            size: A4 landscape;
                            margin: 0;
                        }
                        body {
                            margin: 0;
                            padding: 0;
                            font-family: 'Times New Roman', serif;
                        }
                        .certificate-container {
                            width: 297mm;
                            height: 210mm;
                            background: linear-gradient(135deg, #ffffff 0%, #fefefe 50%, #ffffff 100%);
                            position: relative;
                            overflow: hidden;
                            transform: scale(1) !important;
                        }
                        .certificate-border {
                            border: 12px solid #1f2937;
                            border-radius: 8px;
                            margin: 15px;
                            height: calc(100% - 30px);
                            position: relative;
                            background: linear-gradient(135deg, #ffffff 0%, #f9fafb 100%);
                        }
                        .certificate-inner-border {
                            border: 3px solid #d4af37;
                            border-radius: 4px;
                            margin: 12px;
                            height: calc(100% - 24px);
                            position: relative;
                            background: #ffffff;
                        }
                        .certificate-header {
                            text-align: center;
                            padding: 25px 0 15px 0;
                            border-bottom: 2px solid #d4af37;
                            margin: 0 50px;
                        }
                        .certificate-logo {
                            font-size: 36px;
                            font-weight: 900;
                            color: #1f2937;
                            margin-bottom: 8px;
                            letter-spacing: 4px;
                            font-family: 'Times New Roman', serif;
                        }
                        .certificate-subtitle {
                            color: #4b5563;
                            font-size: 12px;
                            font-weight: 600;
                            letter-spacing: 3px;
                            text-transform: uppercase;
                            font-family: 'Arial', sans-serif;
                        }
                        .certificate-institution {
                            color: #6b7280;
                            font-size: 10px;
                            font-weight: 500;
                            letter-spacing: 2px;
                            text-transform: uppercase;
                            margin-top: 5px;
                            font-family: 'Arial', sans-serif;
                        }
                        .certificate-title {
                            font-size: 28px;
                            font-weight: bold;
                            color: #1f2937;
                            margin: 25px 0 20px 0;
                            letter-spacing: 2px;
                            text-transform: uppercase;
                            font-family: 'Times New Roman', serif;
                        }
                        .certificate-body {
                            text-align: center;
                            padding: 0 80px;
                            line-height: 1.6;
                            font-family: 'Times New Roman', serif;
                        }
                        .certificate-text {
                            font-size: 14px;
                            color: #374151;
                            margin-bottom: 15px;
                            font-weight: 400;
                        }
                        .certificate-name {
                            font-size: 32px;
                            font-weight: bold;
                            color: #1f2937;
                            margin: 20px 0;
                            border-bottom: 2px solid #d4af37;
                            display: inline-block;
                            padding-bottom: 5px;
                            font-family: 'Times New Roman', serif;
                        }
                        .certificate-subject {
                            font-size: 20px;
                            font-weight: bold;
                            color: #1f2937;
                            margin: 20px 0;
                            text-transform: uppercase;
                            letter-spacing: 1px;
                            font-family: 'Times New Roman', serif;
                        }
                        .certificate-achievement {
                            font-size: 13px;
                            color: #374151;
                            margin: 15px 0;
                            font-style: italic;
                        }
                        .certificate-footer {
                            position: absolute;
                            bottom: 30px;
                            left: 0;
                            right: 0;
                            padding: 0 50px;
                        }
                        .certificate-signatures {
                            display: flex;
                            justify-content: space-between;
                            align-items: end;
                            margin-top: 40px;
                        }
                        .signature-section {
                            text-align: center;
                            position: relative;
                            width: 180px;
                        }
                        .signature-line {
                            width: 180px;
                            border-top: 1px solid #374151;
                            margin-bottom: 8px;
                        }
                        .signature-label {
                            font-size: 11px;
                            color: #4b5563;
                            font-weight: 600;
                            text-transform: uppercase;
                            letter-spacing: 1px;
                            font-family: 'Arial', sans-serif;
                        }
                        .signature-title {
                            font-size: 10px;
                            color: #6b7280;
                            margin-top: 3px;
                            font-family: 'Arial', sans-serif;
                        }
                        .certificate-seal {
                            position: absolute;
                            top: 40%;
                            right: 50px;
                            transform: translateY(-50%);
                            width: 100px;
                            height: 100px;
                            border: 3px solid #d4af37;
                            border-radius: 50%;
                            display: flex;
                            flex-direction: column;
                            align-items: center;
                            justify-content: center;
                            background: radial-gradient(circle, #fef3c7 0%, #f59e0b 100%);
                        }
                        .seal-text {
                            font-size: 8px;
                            font-weight: bold;
                            color: #92400e;
                            text-align: center;
                            line-height: 1.1;
                            font-family: 'Arial', sans-serif;
                        }
                        .certificate-date-section {
                            position: absolute;
                            bottom: 30px;
                            right: 50px;
                            text-align: center;
                            font-family: 'Times New Roman', serif;
                        }
                        .certificate-date {
                            font-size: 11px;
                            color: #374151;
                            font-weight: 500;
                        }
                        .certificate-decorations {
                            position: absolute;
                            top: 0;
                            left: 0;
                            right: 0;
                            bottom: 0;
                            pointer-events: none;
                            overflow: hidden;
                        }
                        .decoration-corner {
                            position: absolute;
                            width: 60px;
                            height: 60px;
                            background: linear-gradient(45deg, rgba(212, 175, 55, 0.1) 0%, transparent 70%);
                        }
                        .decoration-corner.top-left {
                            top: 0;
                            left: 0;
                            border-radius: 0 0 60px 0;
                        }
                        .decoration-corner.top-right {
                            top: 0;
                            right: 0;
                            border-radius: 0 0 0 60px;
                        }
                        .decoration-corner.bottom-left {
                            bottom: 0;
                            left: 0;
                            border-radius: 0 60px 0 0;
                        }
                        .decoration-corner.bottom-right {
                            bottom: 0;
                            right: 0;
                            border-radius: 60px 0 0 0;
                        }
                    </style>
                </head>
                <body>
                    ${certificateHTML}
                </body>
                </html>
            `);
            
            printWindow.document.close();
            printWindow.focus();
            printWindow.print();
            printWindow.close();
        }
        
        // Enrollment functions for students
        function unenrollFromSubject(subjectId, subjectName) {
            if (confirm(`Are you sure you want to unenroll from "${subjectName}"?`)) {
                fetch(`/subject/${subjectId}/unenroll`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        location.reload(); // Refresh to show updated enrollment status
                    } else {
                        alert('Error: ' + data.message);
                    }
                })
                .catch(error => {
                    alert('An error occurred while unenrolling.');
                });
            }
        }
        
        // Initialize when DOM is loaded
        document.addEventListener('DOMContentLoaded', function() {
            // Setup search for teachers
            setupSearch('subject-search', 'subjects-container', '.subject-card', ['subjectName', 'subjectDescription']);
            setupSearch('quiz-search', 'quizzes-container', '.quiz-card', ['quizTitle', 'subject']);
            setupSubjectFilter('subject-filter', 'quizzes-container');
            
            // Setup search for students
            setupSearch('enrolled-subject-search', 'enrolled-subjects-container', '.subject-card', ['subjectName', 'subjectDescription', 'teacherName']);
            setupSearch('student-quiz-search', 'student-quizzes-container', '.quiz-card', ['quizTitle', 'subject']);
            setupSubjectFilter('student-subject-filter', 'student-quizzes-container');
            
            // Certificate download buttons
            document.querySelectorAll('.download-certificate-btn').forEach(button => {
                button.addEventListener('click', function() {
                    const subjectId = this.dataset.subjectId;
                    const subjectName = this.dataset.subjectName;
                    generateCertificate(subjectId, subjectName);
                });
            });
            
            // Quiz take buttons
            document.querySelectorAll('.quiz-take-btn').forEach(button => {
                button.addEventListener('click', function() {
                    const quizId = this.dataset.quizId;
                    window.location.href = `/quiz/${quizId}/take`;
                });
            });
            
            // Quiz results buttons
            document.querySelectorAll('.quiz-results-btn').forEach(button => {
                button.addEventListener('click', function() {
                    const quizId = this.dataset.quizId;
                    window.location.href = `/quiz/${quizId}/results`;
                });
            });
            
            // Quiz preview buttons (for teachers)
            document.querySelectorAll('.quiz-preview-btn').forEach(button => {
                button.addEventListener('click', function() {
                    const quizId = this.dataset.quizId;
                    window.location.href = `/quiz/${quizId}/preview`;
                });
            });
        });