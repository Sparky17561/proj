document.addEventListener("DOMContentLoaded", function () {
  // Get the submit button element
  var submitButton = document.getElementById("submit-button");

  // Add click event listener to the submit button
  if (submitButton) {
    submitButton.addEventListener("click", function () {
      simulateUpload();
    });
  }

  // Define the handleFiles function
  window.handleFiles = function (files) {
    const fileList = document.getElementById("file-display");
    fileList.innerHTML = "";
    for (let i = 0; i < files.length; i++) {
      const li = document.createElement("li");
      li.textContent = files[i].name;
      fileList.appendChild(li);
    }
  };

  // Define the simulateUpload function
  window.simulateUpload = function () {
    const fileList = document.getElementById("file-display");
    if (fileList.innerHTML === "No files selected") {
      alert("Please select a file to upload.");
      return;
    }
    // Redirect to the success view
    window.location.href = "/api/success/";
  };

  // Define the cancelUpload function
  window.cancelUpload = function () {
    document.getElementById("fileElem").value = "";
    document.getElementById("file-display").innerHTML = "No files selected";
  };
});

document.getElementById('feedback-form').addEventListener('check', function(event) {
  event.preventDefault(); // Prevent the default form submission

  const email = document.getElementById('email').value.trim();
  const proof = document.getElementById('proof').value.trim();

  // Check if fields are empty
  if (email === "" || proof === "") {
      alert("Please fill in both the email and proof fields.");
      return;
  }

  // Submit data via AJAX using Fetch API
  fetch("{% url 'display_email' %}", {  // Ensure this URL is correctly processed by Django
      method: 'POST',
      headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'X-CSRFToken': '{{ csrf_token }}'  // Include CSRF token for security
      },
      body: new URLSearchParams({
          'email': email,
          'proof': proof
      })
  })
  .then(response => response.json())
  .then(data => {
      alert(data.message);  // Show a message based on server response

      // Clear the form fields if submission is successful
      if (data.status === 'success') {
          document.getElementById('email').value = "";
          document.getElementById('proof').value = "";
      }
  })
  .catch(error => console.error('Error:', error));
});

document.getElementById('url-form').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const url = document.getElementById('url-input').value;
    fetch('/your-django-endpoint/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrftoken')  // Replace this with the actual CSRF token retrieval if needed
        },
        body: JSON.stringify({ url: url })
    })
    .then(response => response.json())
    .then(data => {
        displayReport(data);
    })
    .catch(error => console.error('Error:', error));
});
