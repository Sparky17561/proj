let spamChartInstance = null;  // Store the spam chart instance
let sentimentChartInstance = null; // Store the sentiment chart instance

document.addEventListener("DOMContentLoaded", function () {
    // Handle Analyze Button Click
    document.getElementById("analyze-button").addEventListener("click", analyzeComments);
    
    // Handle URL Analysis Button Click
    document.querySelector('.url-analyze-button').addEventListener("click", analyzeComments);

    // Handle Submit Button Click
    const submitButton = document.getElementById("submit-button");
    if (submitButton) {
        submitButton.addEventListener("click", function() {
            alert("Submit button clicked!"); // Simulate submission logic here
        });
    }

    // Analyze Comments Function
    function analyzeComments() {
        const videoUrl = document.getElementById('video-url').value;

        // Ensure the video URL is not empty
        if (!videoUrl) {
            alert('Please enter a video URL.');
            return;
        }

        console.log('Analyzing comments for URL:', videoUrl);

        // Prepare the request
        fetch('/analyze_comments/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCookie('csrftoken')
            },
            body: JSON.stringify({
                video_url: videoUrl,
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
        const suspiciousCommentsList = document.getElementById('suspicious-comments-list');
        suspiciousCommentsList.innerHTML = ''; // Clear previous comments

        // Update suspicious comments (spam comments only)
        data.spam_comments.forEach(comment => {
            const li = document.createElement('li');
            li.textContent = comment.comment; // Access comment text
            suspiciousCommentsList.appendChild(li);
        });

        // Update spam ratios in the URL analysis section
        const urlAnalysisResult = document.getElementById('url-analysis-result');
        urlAnalysisResult.textContent = `${data.spam_ratio.spam} Spam, ${data.spam_ratio.not_spam} Not Spam`;

        // Update charts based on data
        updateSpamChart(data.spam_ratio); // Pass the correct data
        updateSentimentChart(data.sentiment_ratio); // Pass the correct data
    }

    // Function to update the Spam Chart
    function updateSpamChart(data) {
        const spamCtx = document.getElementById('spamChart').getContext('2d');

        if (spamChartInstance) {
            spamChartInstance.destroy();
        }

        spamChartInstance = new Chart(spamCtx, {
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
    }

    // Function to update the Sentiment Chart
    function updateSentimentChart(data) {
        const sentimentCtx = document.getElementById('sentimentChart').getContext('2d');

        if (sentimentChartInstance) {
            sentimentChartInstance.destroy();
        }

        sentimentChartInstance = new Chart(sentimentCtx, {
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
    }
});
