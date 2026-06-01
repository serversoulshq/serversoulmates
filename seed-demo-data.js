const demoPassword = "DemoOnly-Change-Me-4821";
const demos = [
  ["Aanya", "Woman", "Women", "2003-04-18", "3rd Year", "Biology", "Hostel 3", "Madhya Pradesh", "You'll most likely find me on campus at...", "The library steps with coffee after sunset.", "https://randomuser.me/api/portraits/women/44.jpg"],
  ["Kabir", "Man", "Everyone", "2002-10-09", "4th Year", "Physics", "Hostel 6", "Delhi", "Best spot to skip class and hang out...", "Behind the lecture hall when the weather is good.", "https://randomuser.me/api/portraits/men/32.jpg"],
  ["Meera", "Woman", "Men", "2004-01-26", "2nd Year", "Chemistry", "Hostel 5", "Kerala", "My go-to survival meal during finals is...", "Maggi, chai, and questionable optimism.", "https://randomuser.me/api/portraits/women/68.jpg"],
  ["Arjun", "Man", "Women", "2003-07-13", "3rd Year", "Mathematics", "Hostel 2", "Rajasthan", "Most controversial opinion about the dining hall...", "Breakfast is the only meal worth waking up for.", "https://randomuser.me/api/portraits/men/75.jpg"],
  ["Ira", "Woman", "Everyone", "2002-12-02", "4th Year", "Computer Science", "Hostel 9", "Maharashtra", "You'll most likely find me on campus at...", "A quiet corner with headphones and a half-finished project.", "https://randomuser.me/api/portraits/women/65.jpg"],
  ["Rohan", "Man", "Men", "2004-05-30", "2nd Year", "Natural Sciences", "Hostel 7", "West Bengal", "Best spot to skip class and hang out...", "Anywhere with trees and a decent breeze.", "https://randomuser.me/api/portraits/men/86.jpg"]
];

async function getOrCreateUser(sb, index, firstName) {
  const email = `demo.${firstName.toLowerCase()}@serversouls.local`;
  const { data, error } = await sb.auth.admin.createUser({
    email,
    password: demoPassword,
    email_confirm: true
  });

  if (!error) return data.user;
  if (!error.message.toLowerCase().includes("already")) throw error;

  const { data: listed, error: listError } = await sb.auth.admin.listUsers({ page: 1, perPage: 1000 });
  if (listError) throw listError;
  const existing = listed.users.find(user => user.email === email);
  if (!existing) throw new Error(`Could not find existing demo user ${index + 1}: ${email}`);
  return existing;
}

async function uploadPhotoToStorage(sb, url, userId, index) {
  const fetch = require("node-fetch");
  const response = await fetch(url);
  const buffer = await response.buffer();
  const filePath = `${userId}/${Date.now()}_${index}.jpg`;
  const { error } = await sb.storage.from("profile_images").upload(filePath, buffer, { upsert: true });
  if (error) throw error;
  const { data: publicUrlData } = sb.storage.from("profile_images").getPublicUrl(filePath);
  return publicUrlData.publicUrl;
}

async function seedDemoProfiles(sb) {
  const photoRows = [];

  for (const [index, demo] of demos.entries()) {
    const [firstName, gender, lookingFor, dob, year, major, hostel, homeState, promptQuestion, promptAnswer, photo] = demo;
    const user = await getOrCreateUser(sb, index, firstName);

    const { error: profileError } = await sb.from("profiles").upsert({
      id: user.id,
      email: user.email,
      first_name: firstName,
      gender,
      looking_for: lookingFor,
      dob,
      year,
      major,
      hostel,
      home_state: homeState,
      prompt_question: promptQuestion,
      prompt_answer: promptAnswer
    }, { onConflict: "id" });
    if (profileError) throw profileError;

    const uploadedUrl = await uploadPhotoToStorage(sb, photo, user.id, index);
    photoRows.push({ user_id: user.id, url: uploadedUrl, position: index });
  }

  const demoIds = photoRows.map(row => row.user_id);
  const { error: deleteError } = await sb.from("photos").delete().in("user_id", demoIds);
  if (deleteError) throw deleteError;

  const { error: photoError } = await sb.from("photos").insert(photoRows);
  if (photoError) throw photoError;

  return { seeded: demos.length };
}

module.exports = { seedDemoProfiles };