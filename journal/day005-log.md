## Daily Journal – June 20, 2025

### General Status:

Productive day with a hard pivot in course correction. Cleaned out legacy material, made clear decisions about what not to waste time on, and advanced skills in regex and scanning. Gained deeper clarity on tool importance, scripting potential, and operational approach.

---

### Completed Tasks

CEH Videos
* Reviewed Module 12 – Pulled useful notes on IDS evasion (insertion/obfuscation) and honeypot logic
* Module 14 skimmed briefly – found minimal value
* Overall takeaway: For me, CEH video content is redundant; similar to Security+ and CCNA, and not worth full time investment going forward
* Decision: Remove CEH curriculum from daily plan, replace with focused YouTube/PDF/video research

Python – Automate the Boring Stuff, Chapter 9
* Completed reading: Pages 186–195
* Learned `re.compile()`, `re.search()`, `re.findall()`
* Practiced patterns for phone numbers, IPs, emails
* Bonus script written to extract IPs/emails from files
* Gained major insight: regex shrinks problem complexity drastically and empowers parsing

Cisco Ethical Hacker – Module 3.2
* Completed full module on scanning types and stealth/active techniques
* Observed overlap with previous network security training
* Took note of tooling details and stealth logic
* VM environment issues resolved manually (Cisco’s Kali image repo was misconfigured)

---

### Reflections

I’m starting to see where I’ve outgrown certain educational models. CEH content isn’t moving the needle, and I don’t need to validate what I already understand with hours of slow video. Making decisions about what to cut is as important as deciding what to pursue.

Regex opened up a huge new level of parsing efficiency. What I thought would be tedious procedural code turned out to be one of the cleanest and most powerful ways to manipulate input. This alone makes Python worth mastering.

If stealth fails, use chaos. If a system is too well-defended for silent probing, overwhelm its detection layer with enough noise to bury your real signal. It’s not always about hiding — sometimes it’s about weaponizing overload.