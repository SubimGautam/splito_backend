const mongoose = require("mongoose");
const colors = require("colors");
const dotenv = require("dotenv");
const Batch = require("./models/batch_model");
const Student = require("./models/student_model");
const Category = require("./models/category_model");
const Item = require("./models/items_model");
const Comment = require("./models/comment_model");

// Load env vars
dotenv.config({ path: "./config/config.env" });

// Connect to database
const connectDB = async () => {
  const conn = await mongoose.connect(process.env.LOCAL_DATABASE_URI);
  console.log(`MongoDB Connected: ${conn.connection.host}`.cyan.underline.bold);
};

// Dummy data
const batches = [
  { batchName: "35-A", status: "active" },
  { batchName: "35-B", status: "active" },
  { batchName: "35-C", status: "active" },
  { batchName: "35-D", status: "active" },
  { batchName: "36-A", status: "active" },
  { batchName: "36-B", status: "active" },
  { batchName: "36-C", status: "active" },
  { batchName: "36-D", status: "active" },
];

const categories = [
  {
    name: "Electronics",
    description: "Phones, laptops, chargers, earbuds, etc.",
    status: "active",
  },
  {
    name: "Bags & Accessories",
    description: "Backpacks, wallets, purses, keychains",
    status: "active",
  },
  {
    name: "Clothing",
    description: "Jackets, hoodies, shoes, hats",
    status: "active",
  },
  {
    name: "Books & Stationery",
    description: "Textbooks, notebooks, calculators, pens",
    status: "active",
  },
  {
    name: "ID & Cards",
    description: "Student ID, credit cards, access cards",
    status: "active",
  },
  {
    name: "Keys",
    description: "Car keys, room keys, bike locks",
    status: "active",
  },
  {
    name: "Sports & Fitness",
    description: "Water bottles, fitness trackers, sports gear",
    status: "active",
  },
  {
    name: "Jewelry",
    description: "Necklaces, rings, watches, bracelets",
    status: "active",
  },
  {
    name: "Eyewear",
    description: "Glasses, sunglasses, contact lens cases",
    status: "active",
  },
  { name: "Others", description: "Miscellaneous items", status: "active" },
];

const students = [
  {
    name: "Kiran Rana",
    email: "kiranrana@softwarica.edu.np",
    username: "kiranr",
    password: "password123",
    phoneNumber: "+977-9801234500",
    profilePicture: "default-profile.png",
  },
  {
    name: "Sarah Johnson",
    email: "sarah.johnson@softwarica.edu.np",
    username: "sarahj",
    password: "password123",
    phoneNumber: "+977-9801234501",
    profilePicture: "default-profile.png",
  },
  {
    name: "Michael Chen",
    email: "michael.chen@softwarica.edu.np",
    username: "mikechen",
    password: "password123",
    phoneNumber: "+977-9801234502",
    profilePicture: "default-profile.png",
  },
  {
    name: "Emily Rodriguez",
    email: "emily.rodriguez@softwarica.edu.np",
    username: "emilyrod",
    password: "password123",
    phoneNumber: "+977-9801234503",
    profilePicture: "default-profile.png",
  },
  {
    name: "James Wilson",
    email: "james.wilson@softwarica.edu.np",
    username: "jameswilson",
    password: "password123",
    phoneNumber: "+977-9801234504",
    profilePicture: "default-profile.png",
  },
  {
    name: "Priya Patel",
    email: "priya.patel@softwarica.edu.np",
    username: "priyap",
    password: "password123",
    phoneNumber: "+977-9801234505",
    profilePicture: "default-profile.png",
  },
  {
    name: "David Kim",
    email: "david.kim@softwarica.edu.np",
    username: "davidkim",
    password: "password123",
    phoneNumber: "+977-9801234506",
    profilePicture: "default-profile.png",
  },
  {
    name: "Olivia Martinez",
    email: "olivia.martinez@softwarica.edu.np",
    username: "oliviam",
    password: "password123",
    phoneNumber: "+977-9801234507",
    profilePicture: "default-profile.png",
  },
  {
    name: "Ryan Thompson",
    email: "ryan.thompson@softwarica.edu.np",
    username: "ryant",
    password: "password123",
    phoneNumber: "+977-9801234508",
    profilePicture: "default-profile.png",
  },
  {
    name: "Sophia Lee",
    email: "sophia.lee@softwarica.edu.np",
    username: "sophialee",
    password: "password123",
    phoneNumber: "+977-9801234509",
    profilePicture: "default-profile.png",
  },
  {
    name: "Alex Garcia",
    email: "alex.garcia@softwarica.edu.np",
    username: "alexg",
    password: "password123",
    phoneNumber: "+977-9801234510",
    profilePicture: "default-profile.png",
  },
  {
    name: "Emma Brown",
    email: "emma.brown@softwarica.edu.np",
    username: "emmab",
    password: "password123",
    phoneNumber: "+977-9801234511",
    profilePicture: "default-profile.png",
  },
  {
    name: "Daniel Singh",
    email: "daniel.singh@softwarica.edu.np",
    username: "daniels",
    password: "password123",
    phoneNumber: "+977-9801234512",
    profilePicture: "default-profile.png",
  },
];

const items = [
  {
    itemName: "Black backpack",
    description:
      "Lost my bag somewhere near library. Its black NorthFace with spiderman keychain. Has my laptop and charger inside. Please help!",
    type: "lost",
    location: "Library, Ground Floor",
    media: "default.jpg",
    status: "available",
  },
  {
    itemName: "iPhone 14 with blue case",
    description:
      "Found this iPhone near canteen 2nd floor. Blue silicone case, lockscreen has a golden retriever pic. Come get it from lost and found office.",
    type: "found",
    location: "Canteen, 2nd Floor",
    media: "default.jpg",
    status: "available",
  },
  {
    itemName: "Silver Hydroflask",
    description:
      "Anyone seen my hydroflask? Silver one with national park stickers (Yellowstone, Yosemite). Left it in gym locker room I think.",
    type: "lost",
    location: "Gym Locker Room",
    media: "default.jpg",
    status: "available",
  },
  {
    itemName: "TI-84 Calculator",
    description:
      "Found calculator in Room 205 math building after calculus exam. Blue TI-84 Plus with initials RW written on back.",
    type: "found",
    location: "Block A, Room 205",
    media: "default.jpg",
    status: "available",
  },
  {
    itemName: "Brown leather wallet",
    description:
      "URGENT: Lost my wallet! Brown leather bifold, somewhere near parking lot B. Has my student ID, debit card and some cash. Please contact ASAP!",
    type: "lost",
    location: "Parking Lot B",
    media: "default.jpg",
    status: "available",
  },
  {
    itemName: "AirPods Pro",
    description:
      "Found AirPods Pro on bench near the quad. White case with small scratch on top. DM me the last 4 digits of serial number to claim.",
    type: "found",
    location: "Main Quad, Near Fountain",
    media: "default.jpg",
    status: "claimed",
  },
  {
    itemName: "Red Nike hoodie",
    description:
      "Forgot my hoodie in computer lab B-204 yesterday evening. Red Nike hoodie size M. Has my name written on the tag inside.",
    type: "lost",
    location: "Block B, Computer Lab 204",
    media: "default.jpg",
    status: "available",
  },
  {
    itemName: "Car keys with green lanyard",
    description:
      "Found set of keys near Building C entrance. 3 keys including what looks like Honda car key, all on a green lanyard. Hit me up if they're yours!",
    type: "found",
    location: "Block C, Main Entrance",
    media: "default.jpg",
    status: "available",
  },
  {
    itemName: "Prescription glasses",
    description:
      "Left my glasses in auditorium after 9 AM lecture. Black rectangular frames in a hard black case. Can't see anything without them, really need them back!",
    type: "lost",
    location: "Main Auditorium",
    media: "default.jpg",
    status: "available",
  },
  {
    itemName: "Data Structures textbook",
    description:
      "Someone left their DSA textbook (Cormen) in library 3rd floor study area. Has lots of notes and yellow highlighting. Name partially visible on first page.",
    type: "found",
    location: "Library, 3rd Floor Study Area",
    media: "default.jpg",
    status: "available",
  },
  {
    itemName: "Purple floral umbrella",
    description:
      "Lost my umbrella yesterday during the heavy rain. Purple with white flower pattern. Last had it near main gate bus stop.",
    type: "lost",
    location: "Main Gate Bus Stop",
    media: "default.jpg",
    status: "available",
  },
  {
    itemName: "Fitbit Charge 5",
    description:
      "Found Fitbit Charge 5 in men's locker room near the showers. Black band, still has battery. Come to gym office to identify and claim.",
    type: "found",
    location: "Gym, Men's Locker Room",
    media: "default.jpg",
    status: "available",
  },
  {
    itemName: "White lab coat",
    description:
      "Lost my lab coat somewhere in chemistry building. White, size L, has name 'J. Wilson' embroidered on pocket. Need it for tomorrow's lab!",
    type: "lost",
    location: "Chemistry Building, Lab 3",
    media: "default.jpg",
    status: "resolved",
  },
  {
    itemName: "64GB SanDisk pendrive",
    description:
      "Found a SanDisk USB drive near computer center entrance. 64GB, red and black color. Looks like it has project files. Check with IT desk.",
    type: "found",
    location: "Computer Center, Main Entrance",
    media: "default.jpg",
    status: "available",
  },
  {
    itemName: "Element skateboard",
    description:
      "My skateboard went missing from student center bike rack area. Element brand deck with custom galaxy grip tape. Been looking everywhere for 2 days now.",
    type: "lost",
    location: "Student Center, Bike Rack Area",
    media: "default.jpg",
    status: "available",
  },
  {
    itemName: "MacBook charger",
    description:
      "Found MacBook charger (USB-C) left plugged in at library study room 4. White Apple charger with cable. Available at library front desk.",
    type: "found",
    location: "Library, Study Room 4",
    media: "default.jpg",
    status: "available",
  },
  {
    itemName: "Gold necklace with pendant",
    description:
      "Lost my gold chain necklace with heart pendant near girls hostel area. Has huge sentimental value, was my grandmother's. Please contact if found!",
    type: "lost",
    location: "Girls Hostel, Near Garden",
    media: "default.jpg",
    status: "available",
  },
  {
    itemName: "Blue JBL speaker",
    description:
      "Found JBL Flip 5 bluetooth speaker in cafeteria outdoor seating. Blue color. Turned it in to student services office.",
    type: "found",
    location: "Cafeteria, Outdoor Seating",
    media: "default.jpg",
    status: "claimed",
  },
  {
    itemName: "Student ID card",
    description:
      "Found student ID card for someone named 'Priya P.' near ATM outside main building. Card is at security office.",
    type: "found",
    location: "Main Building, ATM Area",
    media: "default.jpg",
    status: "resolved",
  },
  {
    itemName: "Black leather jacket",
    description:
      "Left my leather jacket at Friday night's cultural event in auditorium. Black, medium size, has inside pocket with zipper. Reward offered!",
    type: "lost",
    location: "Main Auditorium",
    media: "default.jpg",
    status: "available",
  },
  {
    itemName: "Wireless mouse",
    description:
      "Found Logitech wireless mouse in computer lab A-101. Grey color with USB receiver still plugged in nearby computer. At lab assistant desk.",
    type: "found",
    location: "Block A, Computer Lab 101",
    media: "default.jpg",
    status: "available",
  },
  {
    itemName: "Chemistry lab manual",
    description:
      "Lost my chemistry lab manual with all my experiment reports. Blue cover, has my roll number 2023BCA045 written on it. Last seen in Block D.",
    type: "lost",
    location: "Block D, 2nd Floor",
    media: "default.jpg",
    status: "available",
  },
  {
    itemName: "Samsung Galaxy Buds",
    description:
      "Found Samsung Galaxy Buds (white) in the basketball court bleachers. Case has a small crack. Contact me with proof of purchase to claim.",
    type: "found",
    location: "Basketball Court, Bleachers",
    media: "default.jpg",
    status: "available",
  },
  {
    itemName: "Denim jacket",
    description:
      "Missing my favorite denim jacket! Light blue, has some patches on it including a NASA logo. Think I left it in the cafeteria last Tuesday.",
    type: "lost",
    location: "Cafeteria, Indoor Seating",
    media: "default.jpg",
    status: "available",
  },
  {
    itemName: "Power bank 20000mAh",
    description:
      "Found Anker power bank near parking lot vending machine. Black, 20000mAh. Has someone's initials scratched on back. At security booth.",
    type: "found",
    location: "Parking Lot, Vending Machine",
    media: "default.jpg",
    status: "available",
  },
];

const comments = [
  {
    text: "I think I saw this near library yesterday around 4pm. Did you check with the lost and found office?",
  },
  {
    text: "Hey @sarahj I found it! Come to library front desk to pick it up.",
  },
  {
    text: "Is it the plain blue case or the sparkly one? My friend lost a similar phone.",
  },
  {
    text: "Same thing happened to me last week. Hope you find it soon!",
  },
  {
    text: "Wait this might be mine! Can you tell me the last 4 digits of serial number?",
  },
  {
    text: "That's rough. I'll ask around and let you know if anyone has seen it.",
  },
  {
    text: "This could be mine. What brand is the case exactly?",
  },
  {
    text: "Is this still available? I think it belongs to my roommate.",
  },
  {
    text: "Saw someone wearing a red hoodie near gym this morning. Might be yours?",
  },
  {
    text: "These might be my roommate's keys! Are they still with you?",
  },
  {
    text: "I was in that lab yesterday. Didn't see any hoodie though. Maybe check with the lab assistant?",
  },
  {
    text: "Upvoting for visibility. Hope you find your wallet soon!",
  },
  {
    text: "Try checking the security office too. They usually collect lost items.",
  },
  {
    text: "@mikechen is this yours? You mentioned losing your calculator.",
  },
  {
    text: "I found a similar looking item near Block B. Could be the same one?",
  },
  {
    text: "Has anyone claimed this yet? My sister lost the same thing last week.",
  },
  {
    text: "Check the cafeteria lost and found box. They found my stuff there once.",
  },
  {
    text: "Posted on the college WhatsApp group too. More eyes the better!",
  },
  {
    text: "Thank you so much for posting this! Just picked it up. Really appreciate it!",
  },
  {
    text: "Still looking for this? I might have seen something similar in parking lot.",
  },
  {
    text: "Try the security booth near main gate. They keep found items for a week.",
  },
  {
    text: "Is there any reward? Just kidding, but seriously hope you find it!",
  },
  {
    text: "I'll keep an eye out during my evening walk around campus.",
  },
  {
    text: "Did you check all your class rooms? Sometimes we forget where we last had it.",
  },
  {
    text: "This is why I always put AirTags on my important stuff. Good luck though!",
  },
  {
    text: "Just shared this post with my batch group. Someone might have seen it.",
  },
  {
    text: "Contact campus security. They have CCTV footage that might help.",
  },
  {
    text: "Glad this community exists! Found my lost phone through this app last month.",
  },
  {
    text: "Hey @priyap this looks like your ID card! Check this post.",
  },
  {
    text: "Any updates on this? Did you find it?",
  },
];

// Import data
const importData = async () => {
  try {
    await connectDB();

    // Clear existing data
    await Batch.deleteMany();
    await Category.deleteMany();
    await Student.deleteMany();
    await Item.deleteMany();
    await Comment.deleteMany();
    console.log("Data Destroyed...".red.inverse);

    // Create batches
    const createdBatches = await Batch.insertMany(batches);
    console.log(`${createdBatches.length} Batches created`.green.inverse);

    // Create categories
    const createdCategories = await Category.insertMany(categories);
    console.log(`${createdCategories.length} Categories created`.green.inverse);

    // Assign batches to students and create them one by one to trigger password hashing
    const createdStudents = [];
    for (let i = 0; i < students.length; i++) {
      const studentData = {
        ...students[i],
        batchId: createdBatches[i % createdBatches.length]._id,
      };
      const student = await Student.create(studentData);
      createdStudents.push(student);
    }
    console.log(`${createdStudents.length} Students created`.green.inverse);

    // Category mapping for items (index in createdCategories)
    // 0: Electronics, 1: Bags & Accessories, 2: Clothing, 3: Books & Stationery
    // 4: ID & Cards, 5: Keys, 6: Sports & Fitness, 7: Jewelry, 8: Eyewear, 9: Others
    const itemCategoryMap = [
      1, // Black backpack -> Bags & Accessories
      0, // iPhone 14 -> Electronics
      6, // Silver Hydroflask -> Sports & Fitness
      3, // TI-84 Calculator -> Books & Stationery
      1, // Brown leather wallet -> Bags & Accessories
      0, // AirPods Pro -> Electronics
      2, // Red Nike hoodie -> Clothing
      5, // Car keys -> Keys
      8, // Prescription glasses -> Eyewear
      3, // Data Structures textbook -> Books & Stationery
      9, // Purple floral umbrella -> Others
      0, // Fitbit Charge 5 -> Electronics
      2, // White lab coat -> Clothing
      0, // 64GB SanDisk pendrive -> Electronics
      9, // Element skateboard -> Others
      0, // MacBook charger -> Electronics
      7, // Gold necklace -> Jewelry
      0, // Blue JBL speaker -> Electronics
      4, // Student ID card -> ID & Cards
      2, // Black leather jacket -> Clothing
      0, // Wireless mouse -> Electronics
      3, // Chemistry lab manual -> Books & Stationery
      0, // Samsung Galaxy Buds -> Electronics
      2, // Denim jacket -> Clothing
      0, // Power bank -> Electronics
    ];

    // Assign students and categories to items
    const itemsWithStudents = items.map((item, index) => {
      const reportedBy = createdStudents[index % createdStudents.length]._id;
      const category = createdCategories[itemCategoryMap[index]]._id;
      const itemData = {
        ...item,
        reportedBy,
        category,
      };

      // Add claimedBy for claimed items
      if (item.status === "claimed" || item.status === "resolved") {
        itemData.claimedBy =
          createdStudents[(index + 1) % createdStudents.length]._id;
        itemData.isClaimed = true;
      }

      return itemData;
    });

    // Create items
    const createdItems = await Item.insertMany(itemsWithStudents);
    console.log(`${createdItems.length} Items created`.green.inverse);

    // Create comments
    const commentsWithRefs = comments.map((comment, index) => ({
      ...comment,
      item: createdItems[index % createdItems.length]._id,
      commentedBy: createdStudents[(index + 2) % createdStudents.length]._id,
    }));

    const createdComments = await Comment.insertMany(commentsWithRefs);
    console.log(`${createdComments.length} Comments created`.green.inverse);

    console.log("\n✅ All data imported successfully!".green.bold);
    console.log("\n📊 Summary:".cyan.bold);
    console.log(`   Batches: ${createdBatches.length}`);
    console.log(`   Categories: ${createdCategories.length}`);
    console.log(`   Students: ${createdStudents.length}`);
    console.log(`   Items: ${createdItems.length}`);
    console.log(`   Comments: ${createdComments.length}`);

    console.log(
      "\n🔑 Login Credentials (All passwords: password123):".yellow.bold
    );
    createdStudents.slice(0, 5).forEach((student) => {
      console.log(`   Email: ${student.email} | Username: ${student.username}`);
    });

    process.exit();
  } catch (error) {
    console.error(`Error: ${error}`.red.inverse);
    process.exit(1);
  }
};

// Delete data
const deleteData = async () => {
  try {
    await connectDB();

    await Batch.deleteMany();
    await Category.deleteMany();
    await Student.deleteMany();
    await Item.deleteMany();
    await Comment.deleteMany();

    console.log("Data Destroyed...".red.inverse);
    process.exit();
  } catch (error) {
    console.error(`Error: ${error}`.red.inverse);
    process.exit(1);
  }
};

// Run functions based on command line argument
if (process.argv[2] === "-i") {
  importData();
} else if (process.argv[2] === "-d") {
  deleteData();
} else {
  console.log("Please use -i to import or -d to delete data".yellow);
  process.exit();
}
