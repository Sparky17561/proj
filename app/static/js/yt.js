let spamChartInstance = null;  // Store the spam chart instance
let sentimentChartInstance = null; // Store the sentiment chart instance

document.addEventListener("DOMContentLoaded", function () {
    // Handle Analyze Button Click
    const analyzeButton = document.getElementById("analyze-button");
    if (analyzeButton) {
        analyzeButton.addEventListener("click", analyzeComments);
    }

    // Analyze Comments Function
    function analyzeComments() {
        const videoUrl = document.getElementById('video-url');

        if (!videoUrl || !videoUrl.value) {
            alert('Please enter a video URL.');
            return;
        }

        console.log('Analyzing comments for URL:', videoUrl.value);

        // Prepare the request
        fetch('/analyze_comments/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCookie('csrftoken')
            },
            body: JSON.stringify({
                video_url: videoUrl.value,
                limit: 50,
                sort_by: 'top'
            })
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(errorData => {
                    throw new Error('Error: ' + errorData.error);
                });
            }
            return response.json();
        })
        .then(data => {
            console.log('Received data:', data);
            updateUI(data);
        })
        .catch((error) => {
            console.error('There was a problem with the fetch operation:', error);
            alert('Error: ' + error.message);
        });
    }

    // Function to retrieve CSRF token
    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }

    // Function to update the UI with the results
    function updateUI(data) {
        // Get references to the elements
        const suspiciousCommentsList = document.getElementById('suspicious-comments-list');
        const maliciousUrlsList = document.getElementById('malicious-urls-list'); // Updated ID
        const urlAnalysisResult = document.getElementById('url-analysis-result');

        // Clear previous results
        if (urlAnalysisResult) {
            urlAnalysisResult.innerHTML = ''; // Clear previous analysis result
        }

        // Update suspicious comments (spam comments only)
        if (suspiciousCommentsList) {
            suspiciousCommentsList.innerHTML = ''; // Clear previous comments
            data.spam_comments.forEach(comment => {
                const li = document.createElement('li');
                li.textContent = comment.comment; // Access comment text
                suspiciousCommentsList.appendChild(li);
            });
        }

        // Update the found URLs section
        if (maliciousUrlsList) {
            maliciousUrlsList.innerHTML = ''; // Clear previous URLs
            if (data.malicious_urls && data.malicious_urls.length > 0) {
                data.malicious_urls.forEach(url => {
                    const li = document.createElement('li');
                    li.innerHTML = `<a href="${url}" target="_blank">${url}</a>`; // Make URLs clickable
                    maliciousUrlsList.appendChild(li);
                });
            } else {
                maliciousUrlsList.innerHTML = '<li>No malicious URLs found.</li>'; // Handle case with no malicious URLs
            }
        }

        // Update charts based on data
        if (data.spam_ratio) {
            updateSpamChart(data.spam_ratio);
        }
        if (data.sentiment_ratio) {
            updateSentimentChart(data.sentiment_ratio);
        }

        // Optional: Display a message about the analysis
        if (urlAnalysisResult) {
            urlAnalysisResult.innerHTML = `<p>Analysis completed successfully.</p>`;
        }
    }

    // Function to update the Spam Chart
    function updateSpamChart(data) {
        const spamCtx = document.getElementById('spamChart');

        if (spamCtx) {
            if (spamChartInstance) {
                spamChartInstance.destroy();
            }

            spamChartInstance = new Chart(spamCtx.getContext('2d'), {
                type: 'pie',
                data: {
                    labels: ['Spam', 'Not Spam'],
                    datasets: [{
                        data: [data.spam, data.not_spam],
                        backgroundColor: ['#FF6384', '#36A2EB'],
                        hoverOffset: 4
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'top'
                        }
                    }
                }
            });
        } else {
            console.error("Element with ID 'spamChart' not found.");
        }
    }

    // Function to update the Sentiment Chart
    function updateSentimentChart(data) {
        const sentimentCtx = document.getElementById('sentimentChart');

        if (sentimentCtx) {
            if (sentimentChartInstance) {
                sentimentChartInstance.destroy();
            }

            sentimentChartInstance = new Chart(sentimentCtx.getContext('2d'), {
                type: 'pie',
                data: {
                    labels: ['Bad', 'Good', 'Neutral'],
                    datasets: [{
                        data: [data.bad, data.good, data.neutral],
                        backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56'],
                        hoverOffset: 4
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'top'
                        }
                    }
                }
            });
        } else {
            console.error("Element with ID 'sentimentChart' not found.");
        }
    }
});
