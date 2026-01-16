const axios = require('axios');
const colors = require('colors');

const BASE_URL = 'http://localhost:3000/api/v1';
let authToken = '';
let testStudentId = '';
let testBatchId = '';
let testItemId = '';
let testCommentId = '';

// Test results tracking
const results = {
  passed: 0,
  failed: 0,
  errors: []
};

// Helper function to print test results
function logTest(name, success, error = null) {
  if (success) {
    console.log(`✅ ${name}`.green);
    results.passed++;
  } else {
    console.log(`❌ ${name}`.red);
    if (error) {
      console.log(`   Error: ${error.message}`.yellow);
      if (error.response?.data) {
        console.log(`   Response: ${JSON.stringify(error.response.data)}`.yellow);
      }
    }
    results.failed++;
    results.errors.push({ test: name, error: error?.message || 'Unknown error' });
  }
}

// Test Functions
async function testBatchEndpoints() {
  console.log('\n📦 Testing Batch Endpoints...'.cyan.bold);

  // Create Batch
  try {
    const res = await axios.post(`${BASE_URL}/batches`, {
      batchName: 'Test Batch 2024',
      year: 2024,
      department: 'Computer Science'
    });
    testBatchId = res.data.data._id;
    logTest('POST /batches - Create batch', true);
  } catch (error) {
    logTest('POST /batches - Create batch', false, error);
  }

  // Get All Batches
  try {
    await axios.get(`${BASE_URL}/batches`);
    logTest('GET /batches - Get all batches', true);
  } catch (error) {
    logTest('GET /batches - Get all batches', false, error);
  }

  // Get Batch by ID
  if (testBatchId) {
    try {
      await axios.get(`${BASE_URL}/batches/${testBatchId}`);
      logTest('GET /batches/:id - Get batch by ID', true);
    } catch (error) {
      logTest('GET /batches/:id - Get batch by ID', false, error);
    }
  }

  // Update Batch (Protected - needs auth)
  if (testBatchId && authToken) {
    try {
      await axios.put(`${BASE_URL}/batches/${testBatchId}`, {
        batchName: 'Updated Test Batch 2024'
      }, {
        headers: { Authorization: `Bearer ${authToken}` }
      });
      logTest('PUT /batches/:id - Update batch (protected)', true);
    } catch (error) {
      logTest('PUT /batches/:id - Update batch (protected)', false, error);
    }
  }
}

async function testStudentEndpoints() {
  console.log('\n👨‍🎓 Testing Student Endpoints...'.cyan.bold);

  // Create Student
  try {
    const res = await axios.post(`${BASE_URL}/students`, {
      name: 'Test Student',
      username: 'teststudent' + Date.now(),
      email: `test${Date.now()}@example.com`,
      password: 'password123',
      batchId: testBatchId,
      phoneNumber: '+1234567890'
    });
    testStudentId = res.data.data._id;
    logTest('POST /students - Create student', true);
  } catch (error) {
    logTest('POST /students - Create student', false, error);
  }

  // Login Student
  try {
    const loginEmail = `test${Date.now() - 1000}@example.com`;
    const res = await axios.post(`${BASE_URL}/students/login`, {
      email: loginEmail,
      password: 'password123'
    });
    authToken = res.data.token;
    logTest('POST /students/login - Student login', true);
  } catch (error) {
    // Try with a previously created student
    logTest('POST /students/login - Student login', false, error);
  }

  // Get All Students
  try {
    await axios.get(`${BASE_URL}/students`);
    logTest('GET /students - Get all students', true);
  } catch (error) {
    logTest('GET /students - Get all students', false, error);
  }

  // Get Student by ID
  if (testStudentId) {
    try {
      await axios.get(`${BASE_URL}/students/${testStudentId}`);
      logTest('GET /students/:id - Get student by ID', true);
    } catch (error) {
      logTest('GET /students/:id - Get student by ID', false, error);
    }
  }

  // Update Student (Protected)
  if (testStudentId && authToken) {
    try {
      await axios.put(`${BASE_URL}/students/${testStudentId}`, {
        name: 'Updated Test Student'
      }, {
        headers: { Authorization: `Bearer ${authToken}` }
      });
      logTest('PUT /students/:id - Update student (protected)', true);
    } catch (error) {
      logTest('PUT /students/:id - Update student (protected)', false, error);
    }
  }

  // Delete Student (Protected)
  if (testStudentId && authToken) {
    try {
      await axios.delete(`${BASE_URL}/students/${testStudentId}`, {
        headers: { Authorization: `Bearer ${authToken}` }
      });
      logTest('DELETE /students/:id - Delete student (protected)', true);
    } catch (error) {
      logTest('DELETE /students/:id - Delete student (protected)', false, error);
    }
  }
}

async function testItemEndpoints() {
  console.log('\n📦 Testing Item Endpoints...'.cyan.bold);

  // Create Item (Protected)
  if (authToken && testStudentId) {
    try {
      const res = await axios.post(`${BASE_URL}/items`, {
        itemName: 'Test Lost Item',
        description: 'This is a test item',
        type: 'lost',
        reportedBy: testStudentId
      }, {
        headers: { Authorization: `Bearer ${authToken}` }
      });
      testItemId = res.data.data._id;
      logTest('POST /items - Create item (protected)', true);
    } catch (error) {
      logTest('POST /items - Create item (protected)', false, error);
    }
  }

  // Get All Items
  try {
    await axios.get(`${BASE_URL}/items`);
    logTest('GET /items - Get all items', true);
  } catch (error) {
    logTest('GET /items - Get all items', false, error);
  }

  // Get Item by ID
  if (testItemId) {
    try {
      await axios.get(`${BASE_URL}/items/${testItemId}`);
      logTest('GET /items/:id - Get item by ID', true);
    } catch (error) {
      logTest('GET /items/:id - Get item by ID', false, error);
    }
  }

  // Update Item (Protected)
  if (testItemId && authToken) {
    try {
      await axios.put(`${BASE_URL}/items/${testItemId}`, {
        itemName: 'Updated Test Item'
      }, {
        headers: { Authorization: `Bearer ${authToken}` }
      });
      logTest('PUT /items/:id - Update item (protected)', true);
    } catch (error) {
      logTest('PUT /items/:id - Update item (protected)', false, error);
    }
  }

  // Delete Item (Protected)
  if (testItemId && authToken) {
    try {
      await axios.delete(`${BASE_URL}/items/${testItemId}`, {
        headers: { Authorization: `Bearer ${authToken}` }
      });
      logTest('DELETE /items/:id - Delete item (protected)', true);
    } catch (error) {
      logTest('DELETE /items/:id - Delete item (protected)', false, error);
    }
  }
}

async function testCommentEndpoints() {
  console.log('\n💬 Testing Comment Endpoints...'.cyan.bold);

  // Create Comment (Protected)
  if (authToken && testItemId && testStudentId) {
    try {
      const res = await axios.post(`${BASE_URL}/comments`, {
        text: 'This is a test comment',
        itemId: testItemId,
        commentedBy: testStudentId
      }, {
        headers: { Authorization: `Bearer ${authToken}` }
      });
      testCommentId = res.data.data._id;
      logTest('POST /comments - Create comment (protected)', true);
    } catch (error) {
      logTest('POST /comments - Create comment (protected)', false, error);
    }
  }

  // Get Comments by Item
  if (testItemId) {
    try {
      await axios.get(`${BASE_URL}/comments/item/${testItemId}`);
      logTest('GET /comments/item/:itemId - Get comments by item', true);
    } catch (error) {
      logTest('GET /comments/item/:itemId - Get comments by item', false, error);
    }
  }

  // Update Comment (Protected)
  if (testCommentId && authToken) {
    try {
      await axios.put(`${BASE_URL}/comments/${testCommentId}`, {
        text: 'Updated test comment'
      }, {
        headers: { Authorization: `Bearer ${authToken}` }
      });
      logTest('PUT /comments/:id - Update comment (protected)', true);
    } catch (error) {
      logTest('PUT /comments/:id - Update comment (protected)', false, error);
    }
  }

  // Like Comment (Protected)
  if (testCommentId && authToken && testStudentId) {
    try {
      await axios.post(`${BASE_URL}/comments/${testCommentId}/like`, {
        studentId: testStudentId
      }, {
        headers: { Authorization: `Bearer ${authToken}` }
      });
      logTest('POST /comments/:id/like - Like comment (protected)', true);
    } catch (error) {
      logTest('POST /comments/:id/like - Like comment (protected)', false, error);
    }
  }

  // Delete Comment (Protected)
  if (testCommentId && authToken) {
    try {
      await axios.delete(`${BASE_URL}/comments/${testCommentId}`, {
        headers: { Authorization: `Bearer ${authToken}` }
      });
      logTest('DELETE /comments/:id - Delete comment (protected)', true);
    } catch (error) {
      logTest('DELETE /comments/:id - Delete comment (protected)', false, error);
    }
  }
}

// Main test runner
async function runAllTests() {
  console.log('🚀 Starting API Tests...'.cyan.bold);
  console.log(`Testing API at: ${BASE_URL}`.gray);
  console.log('=' . repeat(60));

  try {
    await testBatchEndpoints();
    await testStudentEndpoints();
    await testItemEndpoints();
    await testCommentEndpoints();
  } catch (error) {
    console.error('Fatal error during testing:'.red, error.message);
  }

  // Print summary
  console.log('\n' + '='.repeat(60));
  console.log('📊 Test Summary'.cyan.bold);
  console.log('='.repeat(60));
  console.log(`✅ Passed: ${results.passed}`.green);
  console.log(`❌ Failed: ${results.failed}`.red);
  console.log(`📈 Total: ${results.passed + results.failed}`);
  console.log(`📊 Success Rate: ${((results.passed / (results.passed + results.failed)) * 100).toFixed(2)}%`);

  if (results.errors.length > 0) {
    console.log('\n❌ Failed Tests Details:'.red.bold);
    results.errors.forEach((err, index) => {
      console.log(`${index + 1}. ${err.test}`.yellow);
      console.log(`   ${err.error}`.gray);
    });
  }

  console.log('\n' + '='.repeat(60));

  process.exit(results.failed > 0 ? 1 : 0);
}

// Check if server is running
async function checkServer() {
  try {
    await axios.get(`${BASE_URL}/batches`);
    return true;
  } catch (error) {
    console.error('❌ Server is not running!'.red.bold);
    console.error(`   Please start your server with: npm run dev`.yellow);
    console.error(`   Error: ${error.message}`.gray);
    return false;
  }
}

// Start tests
(async () => {
  const serverRunning = await checkServer();
  if (serverRunning) {
    await runAllTests();
  } else {
    process.exit(1);
  }
})();
