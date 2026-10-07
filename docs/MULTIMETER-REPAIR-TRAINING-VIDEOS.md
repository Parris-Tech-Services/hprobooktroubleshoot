# Multimeter training: laptop chargers, laptop motherboards and desktop PCs

Updated: 8 October 2026 (Australia/Sydney). Curated by task relevance, not a claim that each video has been watched end-to-end.

## Equipment status
- SCA Hobbyist Digital Multimeter, $15.99, purchased 7 October and **picked up / collected** (owner confirmation, 8 October 2026).
- Storage location, first test, calibration/accuracy and exact meter specifications are **not yet confirmed**.

## Suggested learning path (direct video links)
| Level | Topic | Video | What to practise |
|---|---|---|---|
| 1 | Fundamental DC and continuity | [LED Projects — How to use a multimeter for beginners](https://www.youtube.com/watch?v=OD-VMmPyCo4) | Probe sockets, DC voltage at 1:50, resistance at 14:30, continuity at 31:50 |
| 1 | Charger-specific | [Electro University — How To Test A Laptop Charger With A Multimeter](https://www.youtube.com/watch?v=SW5c5b7b6AY) | Correct voltage range, barrel connector polarity, external DC output |
| 1 | Charger troubleshooting | [HealMyTech — How To Test A Laptop Charger With A Multimeter](https://www.youtube.com/watch?v=-jbD2bXtZqU) | Second explanation of laptop adapter output measurement |
| 2 | Desktop ATX | [Britec09 — Manually Test a PSU With a Multimeter](https://www.youtube.com/watch?v=ac7YMUcMjbw) | Standard ATX pinout and output rail measurements; excludes proprietary PSUs |
| 2 | Desktop ATX | [Lunardi Computers — How to Test a PC ATX Power Supply](https://www.youtube.com/watch?v=DFFXwST08ug) | +3.3V, +5V, +12V, standby rail and limits of paperclip testing |
| 3 | Laptop power rails | [Electronics Repair Basics — Laptop Motherboard No Power, Short Circuit, Part 1](https://www.youtube.com/watch?v=qv8qcpRyYQU) | Fault isolation, voltage rails and careful board diagnostics |

## Longer courses / multi-video learning collections
These are **curated course pages** linking YouTube lessons, not verified YouTube playlist IDs:
- [Electronics Repair School — Laptop Repair Course: USB-C Power Delivery, Diagnostics and Motherboard Troubleshooting](https://www.classcentral.com/course/youtube-laptop-repair-course-513471) — 3h 48m, intermediate; multiple case studies.
- [Electronics Repair School — Laptop Motherboards Repairs: The Power Input Circuit](https://www.classcentral.com/course/youtube-laptop-motherboards-repairs-the-power-input-circuit-147584) — 47m, beginner.
- [Electronics Repair School — Diagnosing Lenovo Laptop: No Power, Not Charging](https://www.classcentral.com/course/youtube-lenovo-laptop-no-power-not-charging-let-s-learn-to-diagnose-147582) — 58m, beginner.
- [Electronics Repair School — Laptop Repair Tutorial 2: Main Power Rail](https://www.classcentral.com/course/youtube-laptop-repair-tutorial-2-how-to-find-and-check-the-main-power-rail-with-your-power-supply-517489) — 25m.
- [SparkFun — How to Use a Multimeter](https://www.classcentral.com/course/youtube-sparkfun-how-to-use-a-multimeter-130905) — 21m, beginner.
- [DroneBot Workshop — Multimeters: Complete Guide](https://www.classcentral.com/course/youtube-multimeters-the-complete-guide-286934) — 59m, beginner.
- [iFixit — Master the Multimeter Basics](https://www.ifixit.com/News/8085/multimeter-basics) — article linking a video on voltage, resistance and continuity.

## Practical learning sequence using Josh's equipment
1. With all power disconnected, practise identifying COM and V/Ω sockets, then continuity on a loose, disconnected cable. **Never test continuity or resistance on a powered circuit.**
2. Identify the rated voltage, polarity and plug type printed on a spare laptop charger; check the meter's DC V function. Only measure accessible low-voltage output using a verified connector pinout. Avoid shorting adjacent contacts or a centre identification pin.
3. Compare a Lenovo 90W supply's label to its DC reading; do not assume all Lenovo connectors have the same pinout.
4. For desktop troubleshooting, inspect the published pinout for the exact PSU, especially proprietary models. Work only at the external low-voltage connector; do not open a PSU.
5. Observe board-level laptop troubleshooting videos before doing live probing or repair. This hobby meter and novice skill level are not a basis for high-energy or mains-level measurement.

## Safety/interpretation
- Australia uses nominal 230V AC mains; this beginner exercise is **low-voltage DC only**. Never open power bricks, laptop chargers or ATX PSUs: capacitors can retain dangerous charge after unplugging.
- Probe setup matters: black in COM and red in V/Ω for voltage; do **not** use the A/mA input for a voltage measurement.
- A correct no-load DC voltage does not prove a charger is healthy under load. A paperclip-started ATX supply is not proof of stability under load.
- If meter ratings, probes, polarity or pinout are uncertain, stop and check documentation first.

## Provenance
Links checked via public search on 8 October 2026. The linked videos and course listings exist; video teaching quality and all electrical procedures have **not** been fully independently audited. Local test results are not yet recorded.
