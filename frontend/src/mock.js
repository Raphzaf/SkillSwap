/*
  SkillSwap mock data and utilities
  - Profiles: name, age, distance, bio, skillsToTeach, skillsToLearn, photos
  - Conversations: seeded with a few mock threads
  - Utilities: nextProfile (infinite deck), randomMatch(prob)
*/

export const CORAL = "#ff6f61";

// Optional: tweak Unsplash params for consistent sizing
const U = (url) => `${url}?auto=format&fit=crop&w=900&q=80`;

export const photoPool = [
  U("https://images.unsplash.com/photo-1502685104226-ee32379fefbe"),
  U("https://images.unsplash.com/photo-1527980965255-d3b416303d12"),
  U("https://images.unsplash.com/photo-1529626455594-4ff0802cfb7e"),
  U("https://images.unsplash.com/photo-1544005313-94ddf0286df2"),
  U("https://images.unsplash.com/photo-1547425260-76bcadfb4f2c"),
  U("https://images.unsplash.com/photo-1541534401786-2077eed87a72"),
  U("https://images.unsplash.com/photo-1544005316-04ceebf53fd8"),
  U("https://images.unsplash.com/photo-1506794778202-cad84cf45f1d"),
];

export const profiles = [
  {
    id: "u1",
    name: "Ava",
    age: 26,
    distanceKm: 3,
    bio: "Designer turned maker. I love rapid prototyping and weekend hackathons.",
    skillsToTeach: ["Figma", "Branding", "Prototyping"],
    skillsToLearn: ["Python", "3D Printing"],
    photos: [photoPool[0]],
  },
  {
    id: "u2",
    name: "Mateo",
    age: 29,
    distanceKm: 5,
    bio: "Frontend engineer exploring creative coding and WebGL.",
    skillsToTeach: ["React", "CSS Animations"],
    skillsToLearn: ["Public Speaking", "Music Theory"],
    photos: [photoPool[1]],
  },
  {
    id: "u3",
    name: "Sofia",
    age: 24,
    distanceKm: 2,
    bio: "Barista by day, aspiring photographer by night.",
    skillsToTeach: ["Latte Art", "Portrait Photography"],
    skillsToLearn: ["Copywriting", "Javascript"],
    photos: [photoPool[2]],
  },
  {
    id: "u4",
    name: "Noah",
    age: 31,
    distanceKm: 11,
    bio: "Product manager who enjoys woodworking and trail running.",
    skillsToTeach: ["Roadmapping", "Interviewing"],
    skillsToLearn: ["Woodworking", "UI Design"],
    photos: [photoPool[3]],
  },
  {
    id: "u5",
    name: "Maya",
    age: 27,
    distanceKm: 8,
    bio: "Community builder. I host maker meetups and reading circles.",
    skillsToTeach: ["Community Ops", "Facilitation"],
    skillsToLearn: ["SQL", "Motion Graphics"],
    photos: [photoPool[4]],
  },
  {
    id: "u6",
    name: "Leo",
    age: 34,
    distanceKm: 4,
    bio: "Hardware tinkerer, open-source contributor, cyclist.",
    skillsToTeach: ["Arduino", "Soldering"],
    skillsToLearn: ["Illustration", "Kotlin"],
    photos: [photoPool[5]],
  },
  {
    id: "u7",
    name: "Zara",
    age: 25,
    distanceKm: 6,
    bio: "Language nerd, traveler, and dumpling enthusiast.",
    skillsToTeach: ["Spanish", "French"],
    skillsToLearn: ["Cooking", "Data Viz"],
    photos: [photoPool[6]],
  },
  {
    id: "u8",
    name: "Ethan",
    age: 30,
    distanceKm: 9,
    bio: "Indie hacker building tools for creators.",
    skillsToTeach: ["No-Code", "Analytics"],
    skillsToLearn: ["Piano", "Rust"],
    photos: [photoPool[7]],
  },
];

export const seededConversations = [
  {
    id: "c1",
    userId: "u3",
    name: "Sofia",
    avatar: photoPool[2],
    lastMessage: "I can show you basics of portrait lighting!",
    messages: [
      {
        id: "m1",
        from: "u3",
        text: "Hey! Want to trade coffee lessons for photo tips?",
        ts: Date.now() - 1000 * 60 * 60 * 5,
      },
      {
        id: "m2",
        from: "me",
        text: "Yes! I can teach latte art in return.",
        ts: Date.now() - 1000 * 60 * 60 * 4,
      },
      {
        id: "m3",
        from: "u3",
        text: "Awesome. I can show you basics of portrait lighting!",
        ts: Date.now() - 1000 * 60 * 30,
      },
    ],
  },
  {
    id: "c2",
    userId: "u2",
    name: "Mateo",
    avatar: photoPool[1],
    lastMessage: "Let's plan a short session this weekend?",
    messages: [
      {
        id: "m1",
        from: "u2",
        text: "I can help with CSS animations if you teach me public speaking!",
        ts: Date.now() - 1000 * 60 * 60 * 24,
      },
      { id: "m2", from: "me", text: "Deal!", ts: Date.now() - 1000 * 60 * 60 * 23 },
    ],
  },
];

/**
 * Returns the profile at position (index % profiles.length)
 * If profiles is empty, returns null.
 */
export function nextProfile(index) {
  if (!profiles.length) return null;
  const i = Math.abs(index) % profiles.length;
  // return a shallow copy to avoid accidental mutation outside
  const p = profiles[i];
  return { ...p, photos: [...(p.photos || [])] };
}

/**
 * Returns true with the given probability (default 0.3 = 30%).
 * Example: randomMatch() or randomMatch(0.5) for 50%.
 */
export function randomMatch(prob = 0.3) {
  const p = Math.min(1, Math.max(0, Number(prob) || 0));
  return Math.random() < p;
}

export const defaultUser = {
  id: "me",
  name: "You",
  age: 28,
  photos: [photoPool[0]],
  bio: "New to SkillSwap. Here to teach and learn!",
  skillsToTeach: ["English Conversation"],
  skillsToLearn: ["Javascript"],
};
