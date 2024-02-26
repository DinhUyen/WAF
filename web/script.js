async function fetchData() {
    // Get the params from the page
    let HOST = document.getElementById('host').value;
    let number = document.getElementById('number').value;
    let page = document.getElementById('page').value;
    let filters = document.getElementById('filters').value;
    let distinct = document.getElementById('distinct').checked;
    console.log("HOST: ", HOST, "number: ", number, "page: ", page, "filters: ", filters, "distinct: ", distinct);
    // strip spaces from params
    HOST = HOST.replace(/\s/g, '');
    number = number.replace(/\s/g, '');
    page = page.replace(/\s/g, '');
    filters = filters.replace(/\s/g, '');
    let apiURL = '';
    try {
        // http://45.76.182.199:5555/getlog?number=3&page=1
        apiURL = `${HOST}/getlog?number=${number}`;
        if (page && page !== '') {
            apiURL += `&page=${page}`;
        }
        if (filters && filters !== '') {
            apiURL += `&filters=${filters}`;
        }
        if (distinct === true) {
            apiURL += `&distinct=1`;
        }
        console.log('Fetching data from:', apiURL);
        const response = await fetch(apiURL);
        const data = await response.json();
        console.log('Data fetched:', data);
        displayData(data);
        
    } catch (error) {
        console.error('Error fetching data:', error);
    }
}



// Function to display data on the page
function displayData(data) {
    const logBody = document.getElementById('logBody');
    logBody.innerHTML = '';
    // Iterate through each log entry
    data.forEach(logEntry => {
        // console.log("logEntry: ", logEntry);
        const logRow = document.createElement('tr');
        const base64Msg = btoa(logEntry.msg);
        const base64Message = btoa(logEntry.message);
        
        logRow.innerHTML = `
            <td>${logEntry.id}</td>
            <td>${logEntry.remote_address}</td>
            <td>${logEntry.remote_port}</td>
            <td>${logEntry.local_address}</td>
            <td>${logEntry.local_port}</td>
            <td>${logEntry.request}</td>
            <td>${(logEntry.time || '').substring(0, 20)}</td>
            <td class="msg-cell" data-full-msg="${base64Msg || ''}">${(logEntry.msg || '')}...</td>
            <td class="message-cell" data-full-message="${base64Message || ''}">${(logEntry.message || '')}...</td>
            <!--<td><button onclick="expandMessage(this)">Expand</button></td> -->
        `;
        logBody.appendChild(logRow);
    });
}

// Function to expand the message
function expandMessage(button) {
    const messageCell = button.parentElement.previousElementSibling;
    const msgCell = messageCell.previousElementSibling;
    const fullMessage= atob(messageCell.dataset.fullMessage);
    const fullMsg = atob(msgCell.dataset.fullMsg);
    messageCell.innerText = fullMessage;
    msgCell.innerText = fullMsg;
    button.parentElement.remove();
    
}

// Fetch data initially when the page loads
document.addEventListener('DOMContentLoaded', fetchData);
// Fetch data every 5 seconds
setInterval(fetchData,5000);