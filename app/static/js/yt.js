let spamChartInstance = null;  // Store the spam chart instance
let sentimentChartInstance = null; // Store the sentiment chart instance

document.addEventListener("DOMContentLoaded", function () {
    // Handle Analyze Button Click
    const analyzeButton = document.getElementById("analyze-button");
    if (analyzeButton) {
        analyzeButton.addEventListener("click", analyzeComments);
    }

    // Handle Submit Button Click
    const submitButton = document.getElementById("submit-button");
    if (submitButton) {
        submitButton.addEventListener("click", function() {
            alert("Submit button clicked!"); // Simulate submission logic here
        });
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
        const urlAnalysisResult = document.getElementById('url-analysis-result');
        const foundUrlsList = document.getElementById('found-urls-list'); // Get the found URLs list element

        // Check if elements exist before trying to update them
        if (suspiciousCommentsList) {
            suspiciousCommentsList.innerHTML = ''; // Clear previous comments

            // Update suspicious comments (spam comments only)
            data.spam_comments.forEach(comment => {
                const li = document.createElement('li');
                li.textContent = comment.comment; // Access comment text
                suspiciousCommentsList.appendChild(li);
            });
        } else {
            console.error("Element with ID 'suspicious-comments-list' not found.");
        }

        if (urlAnalysisResult) {
            urlAnalysisResult.textContent = `${data.spam_ratio.spam} Spam, ${data.spam_ratio.not_spam} Not Spam`;
        } else {
            console.error("Element with ID 'url-analysis-result' not found.");
        }

        // Clear the URLs list before adding new entries
        if (foundUrlsList) {
            foundUrlsList.innerHTML = ''; // Clear previous URLs

            // Update the found URLs section
            data.found_urls.forEach(url => {
                const li = document.createElement('li');
                li.innerHTML = `<a href="${url}" target="_blank">${url}</a>`; // Make URLs clickable
                foundUrlsList.appendChild(li);
            });
        } else {
            console.error("Element with ID 'found-urls-list' not found.");
        }

        // Update charts based on data
        if (data.spam_ratio) {
            updateSpamChart(data.spam_ratio); // Pass the correct data
        }
        if (data.sentiment_ratio) {
            updateSentimentChart(data.sentiment_ratio); // Pass the correct data
        }
    }

    // Function to update the Spam Chart
    function updateSpamChart(data) {
        const spamCtx = document.getElementById('spamChart');
        
        if (!spamCtx) {
            console.error("Element with ID 'spamChart' not found.");
            return;
        }

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
    }

    // Function to update the Sentiment Chart
    function updateSentimentChart(data) {
        const sentimentCtx = document.getElementById('sentimentChart');
        
        if (!sentimentCtx) {
            console.error("Element with ID 'sentimentChart' not found.");
            return;
        }

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
    }
});
