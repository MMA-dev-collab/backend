const http = require('http');

const options = {
  hostname: '127.0.0.1',
  port: 4000,
  path: '/api/cases',
  method: 'GET',
  headers: {
    'ngrok-skip-browser-warning': 'true'
  }
};

const req = http.request(options, (res) => {
  let data = '';
  console.log(`Status Code: ${res.statusCode}`);
  
  res.on('data', (chunk) => {
    data += chunk;
  });

  res.on('end', () => {
    try {
      const parsed = JSON.parse(data);
      console.log('Response data length:', parsed.data ? parsed.data.length : 'N/A');
      if (parsed.data && parsed.data.length > 0) {
        console.log('First case title:', parsed.data[0].title);
      }
      console.log('Full Response Meta:', JSON.stringify(parsed.meta, null, 2));
    } catch (e) {
      console.log('Raw Response:', data);
    }
  });
});

req.on('error', (e) => {
  console.error(`Problem with request: ${e.message}`);
});

req.end();
