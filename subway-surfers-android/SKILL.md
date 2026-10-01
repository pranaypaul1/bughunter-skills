---
name: subway-surfers-android
description: Play Subway Surfers (com.kiloo.subwaysurf) on the user's USB-connected Android phone from the Linux laptop - game rules, which swipe beats which obstacle, and the tested control stack (scrcpy live frames + persistent adb swipes, code in ~/Documents/subsurf-bot/). Use whenever the user asks to play, test, automate, or "run" Subway Surfers or another real-time Android game on the phone, or to build/tune the bot. Includes tutorial quirks and what already failed, so nothing has to be re-learned.
---

# Subway Surfers on the user's phone

Everything below is tagged **[verified]** (measured or seen on this phone) or **[sourced]** (from web docs, not re-checked in-game). Don't treat [sourced] items as certain.

## 0. Ground rules (read first)
- The phone is the user's real device with their real accounts. **Ask before starting a run** and before anything that could spend keys/coins/ads. Never tap "revive / save me / watch ad / buy / claim". If a crash screen shows a revive offer, leave it and tell the user.
- Only use `adb`/`scrcpy` against the phone the user connected. Don't touch other apps (WhatsApp, PhonePe, Telegram, Snapchat are on it).
- Real-time play can't be done by Claude itself: one model round-trip is seconds, the game needs a decision every ~100 ms. A **local script** must do the reflexes; Claude builds/tunes/launches it and reads the results. [verified reasoning]

## 1. Game rules
Sources: official Sybo Help Center "Basics", Wikipedia, tips sites (poki/runsubway/subwaysrf).
- **Controls [sourced, official]:** swipe left/right = change lane; swipe up = jump; swipe down = roll (on ground) and *cancels a jump mid-air*; double tap = activate hoverboard.
- **Lanes:** 3 lanes. Camera follows the player laterally, so the player's own lane is always near screen centre-ish (see §3 geometry).
- **Obstacles [sourced]:**
  - Trains: biggest/most frequent - switch lane (or jump onto the roof if a ramp/low train allows; roofs have coins and fewer obstacles). Head-on hit = crash.
  - Barriers: jump over the low ones, roll under the tall/raised ones.
  - Fences (low, mid-track): slide/roll under. Bins near stations: jump.
  - Poles, tunnel walls: dodge by lane change.
- **Crash [sourced]:** hitting an obstacle ends the run; revive costs a **key** or an ad. First hits sometimes only "stumble" (inspector + dog catch you on a 2nd) - [unverified in-game, but we saw a stumble animation with stars when clipping a side wall].
- **Power-ups [sourced]:** jetpack (fly over everything), super sneakers (higher jumps), coin magnet, 2x multiplier, hoverboard (~30 s crash shield).
- **Scoring [sourced]:** score rises while running; multiplier boosts it. In this phone's tutorial the score counter **freezes** while the tutorial is looping (see §4).
- Strategy tips [sourced]: run on train roofs when possible, read patterns, keep keys/boards for good runs.

## 2. Verified hardware/software facts
- Phone: Xiaomi/Redmi `23076RN4BI`, Android 15, arm64, **not rooted**, ADB serial `e3f72948e0a2` (USB). Screen **1080x2460**. Wi-Fi IP 192.168.29.161 (same LAN as laptop).
- Laptop: Kali, `scrcpy 4.1`, `ffmpeg 8.1`, `adb`, python3 + numpy (no cv2/av installed).
- Game package/activity: `com.kiloo.subwaysurf`, focus `com.sybogames.chili.multidex.ChiliMultidexSupportActivity`. Check it's in front: `adb shell dumpsys window | grep mCurrentFocus`.
- `adb exec-out screencap -p` = **~550 ms** per frame -> only for one-off screenshots, never for the loop.

## 3. The control stack (code: `~/Documents/subsurf-bot/`)
| File | What it is |
|---|---|
| `phone.py` | `FrameFeed` (scrcpy -> mkv fifo -> ffmpeg -> raw BGR numpy frames, 236x540, newest kept, `.latest()`), `Input` (one persistent `adb shell`; `.left() .right() .up() .down() .tap() .swipe() .sync()`) |
| `jump_timed.py` | `barrier_y()`, `save(img,name)` (PPM->PNG via ffmpeg), one-shot timed jump/roll test (`python3 jump_timed.py <trigger_y> <up|down>`) |
| `auto_play.py` | Red-barrier bot: `nearest_barrier(img)` -> `(bottom_y, n_wide_bars)`; fires jump or roll |
| `arrow.py`, `tutorial_arrow.py` | Hint-arrow detector + swipe-on-arrow trigger for the tutorial (works, left side verified) |
| `autopilot.py` | Experimental lane-aware bot (trains/freight cars) - **currently unreliable**, see §5 |
| `grab.py`, `watch.py`, `left_test.py`, `right_test.py`, `lane_test.py` | frame/contact-sheet capture helpers (they save `*.png` sheets to view with Read) |

Measured numbers **[verified]**:
- scrcpy feed: ~40 unique frames/s on a moving scene; **first frame takes ~11 s after start** (one-time). Start the feed early and keep it running.
- `adb shell input` via persistent shell: **~66 ms per command**. Gestures (screen px): left `700,1300 -> 300,1300`, right `380,1300 -> 780,1300`, up (jump) `540,1500 -> 540,1000`, down (roll) `540,1000 -> 540,1500`, duration 40 ms. Up, down, left, right **all confirmed working**.
- Frame is 236 wide x 540 tall; phone px = frame px x 4.575. Player sits around frame y 380-470; vanishing point ~ (118, 150).
- Lane spacing at frame y=350 is ~80 px, shrinking linearly to 0 at y~150 (own lane at x~118 because camera follows).
- Total reaction budget ~150-250 ms (feed ~35-70 + decode + swipe ~66 + game input lag): fire early.
- Never pipe scrcpy with `--record=-` (0 bytes). Use a **named pipe** (`mkfifo`) as in `FrameFeed`.
- Importing a script that has no `if __name__ == "__main__"` guard will run it - guard everything.

## 4. First-run tutorial quirks [verified]
The first run after install is a scripted tutorial. It **loops a scenario** (obstacle approaches, player crashes, scene resets ~every 4 s) until the requested move is done correctly:
1. Short barrier (single top bar + chevron board) -> **swipe up (jump)**. Worked when fired at barrier-y ~240 (frame coords).
2. Tall barrier (red-white bar at top AND bottom, legs, gap under it) -> **swipe down (roll)**. Worked; game shows "Fresh Moves!".
3. Freight car / train wall in lane -> **swipe left**, then **swipe right**.
- While looping, **score is frozen** (43, 111, 133, 187, 247...). Score moving again = step accepted.
- A faint **translucent arrow** (pale pink, points in the required direction, sits at the screen edge) appears ~1 s into each cycle. A swipe sent **before** the arrow does nothing; sent while it shows, it counts. Arrow pixels are pale-pink (~RGB 176,132,149 vs wall ~117,74,91); ~60% of pixels in a 50x55 box at the arrow are "pale pink" (R>170,G>110,B>120) vs 0% without it. **Wired up:** `arrow.py` (`arrow_score(img, 'left'|'right')` = count of pale-pink px in the edge band) + `tutorial_arrow.py` (swipes when score >= 1000 left / >= 300 right, 3 s cooldown). Live test: left arrow scored 3052 (baseline <=300, right side <=70), swipe fired 0.1 s in, character changed lane, score moved 247->265 and tutorial step passed. Right-side threshold untested (right arrow looked fainter, ~100 in old frames).
- Always read the on-screen prompt/hint. The user can see the phone live - **ask them what the hint says** if the frames are ambiguous. They will tell you the move (they told us: jump=up, roll=down, then left, then right).
- Left swipe when a train wall is right beside you = clip the wall and stumble. Check the target lane is empty.

## 5. What failed (don't repeat)
- Guessing gestures/timing without evidence. Always: capture frames before/after, view the contact sheet, check the score counter.
- Barrier "height" from red-row clustering: chevron rows are too thin, tall barrier measured 22 px and got a jump into a wall. **Fixed** by counting *wide solid-red bars* (>=40 red px per row): 2 bars = tall = roll, 1 = short = jump. (Short-barrier case not re-tested since the fix.)
- Firing before the tutorial reset finished, on a leftover barrier: require the barrier's y to be **rising over 4 frames**, ignore the first second, use a 1.6 s cooldown.
- Colour-based lane occupancy (`autopilot.py`, "median B-R > -38 = obstacle"): sampled colours were track RGB~(100,52,55) B-R~-45, wooden freight car ~(115,68,84) B-R~-31, purple train B-R > -10 - but **shaded track (RGB~63,29,25) sits at -37..-38**, right on the threshold, and rails/sleepers/the player add noise. Result: obstacles "seen" in almost every lane, the bot spammed jumps and jumped onto a freight car. Needs a better feature or a learned model before trusting it.
- Sending swipes at a random moment in the tutorial cycle.

## 6. How to run a session (checklist)
1. `adb devices` -> `e3f72948e0a2 device`. Game in foreground (`dumpsys window | grep mCurrentFocus`). If not: ask the user, or `adb shell monkey -p com.kiloo.subwaysurf 1`.
2. Screenshot (`adb exec-out screencap -p > $S/x.png`) and **Read** it to see the state (menu "Tap to Play", running, crash/revive, tutorial hint).
3. Ask before starting a run. Start: tap "Tap to Play" (`Input.tap(540, 1500)`).
4. For each new situation: capture a contact sheet (`FrameFeed` frames every ~0.1-0.35 s, 4 per row), send ONE gesture, verify from frames + score, then automate.
5. Keep bot runs short (20-30 s) and view the resulting sheet; report honestly what worked, what crashed, and the score trend.
6. Stop at any revive/ad/purchase prompt and hand back to the user.

## 7. Open work (in priority order)
1. ~~Trigger tutorial swipes off the hint arrow~~ DONE for left; verify the right arrow and any later tutorial steps (roll/jump prompts may also show arrows).
2. Replace colour lane-occupancy with something robust: either fix the feature (exclude shadow, use texture/edges + lane geometry) or train a small CNN on frames (imitation from the user's own play recorded via scrcpy+`adb getevent`, or use https://github.com/Bezet1/subway-surfers-ai / https://github.com/nikp06/subwAI as starting points - not reviewed yet).
3. Handle trains/ramps/roof-running, coins, power-ups, hoverboard (double tap `input tap` twice), crash detection (score stops / crash overlay) and safe stop.
4. Reduce feed start latency (11 s) and swipe latency (try scrcpy control channel instead of `adb shell input`).

## 8. Real-run lessons (first real run after the tutorial)
- Tutorial hints (arrows) are **gone** after the tutorial. Do not wait for or react to arrows in normal play.
- Main menu **PLAY** button = phone px `(855, 2343)`. Results screen -> "Tap to continue" = tap `(540, 1500)` (safe). Menu/result screens show **"Watch Video (Ad)" and "+500 (Ad)"** - never tap them. Account at that time: 5 keys, 10 hoverboards, ~10k coins - **spend nothing** (no Continue, no hoverboard double-tap unless the user says so).
- After a crash a **"Continue?" dialog** appears (key/ad revive, ~few seconds), then the results screen (score, coins). The bot must send **no taps** there.
- **Gameplay detector:** `in_gameplay(img)` in `autopilot2.py` = light-blue pause button top-left of the 236x540 frame (`img[28:58, 6:36]`, fraction of pixels with B>150, B-R>60, G>100 > 0.3). Measured 0.48-0.53 in a run vs <=0.02 on Continue?/results/menu. Stop the bot the moment it leaves gameplay (my first orange-screen check missed the white/blue results screen and the bot swiped up on the menu for 40 s).
- Feed start (~11 s) happens while on the menu; start `FrameFeed` first, then tap PLAY.
- **Camera does NOT keep the player centred** (player x varied ~80-190 in the 236-wide frame). Lane geometry must be laid out around the detected player x, not a fixed centre. Player x from the red cap (R>170,G<80,B<80 in rows 340-480) gave x~32-41 in one run where the character looked central - unreliable, needs checking (barriers/other red things pollute it).
- `autopilot2.py` first real run: score **87**, died in ~5 s (previous best 416 came from the tutorial-phase run). It judged all three lanes "blocked" and just jumped. **Not good enough to call "playing properly".** Obstacle rule tried: G-B <= -11 and R >= 85 (better than B-R for shaded track: shaded track G-B ~ +4, freight car ~ -13..-18, purple train ~ -43).
- Next step that should actually work: learn from data (record frames + swipes while the user plays, or reuse the GitHub CNN projects) instead of hand-tuned colour rules.

## 9. Human-play recorder (imitation-learning data) [verified working]
- `~/Documents/subsurf-bot/record.py [--seconds N] [--out runs/NAME]` - **read-only**: scrcpy frames + `adb shell getevent -lt /dev/input/event1` (touchscreen `fts_ts`, coords are 10x screen px). Sends NO input. Ctrl-C saves.
- Output: `runs/*.npz` (`frames` (N,144,64,3) uint8, `t` frame times, `play` bool = pause-button visible) and `runs/*.json` (gestures: `t_down,t_up,action,dx,dy,x,y`; action in left/right/up/down/tap, swipe if >=60 phone px).
- Gesture parser unit-tested offline (`GestureParser`), and confirmed on real touches (14 gestures in a 20 s self-test). Feed takes ~11 s to start before the first frame; scrcpy only emits frames when the screen changes, so static menus give few frames but gameplay gives ~40 fps.
- Pull-down-from-top swipes (y~0) are the notification shade - filter `y < 100` and non-gameplay frames (`play == False`) when training.
- PyTorch 2.14.0+cpu is installed in `~/Documents/subsurf-bot/.venv` (Python 3.14, CPU only, 8 cores, 7 GB RAM, no NVIDIA GPU). Use `.venv/bin/python`.
- Plan: record 10-20 human runs -> label each frame with the action taken ~0.25 s later (latency compensation; 5 classes incl. "nothing") -> small CNN on stacked frames -> bot with the `in_gameplay` stop-check -> optional RL fine-tune. Record the model version/score here after each training.

## 10. First human recording (rec_20260924_124705) - findings
- File: 1600 frames / 83 s, 31 gestures (8 left, 8 right, 8 up, 3 down, 4 tap); ~42 s continuous gameplay (frames 72-1261) with ~30 swipes, ~0.75 swipes/s while playing. Swipes last 95-243 ms; frame gap median 35 ms. **Far too little to train on** - need ~15+ min of play (~600+ swipes).
- **The pause button has two HUD colours: blue AND yellow** (yellow seen mid-run; unknown trigger). `in_gameplay` originally only knew blue and mislabelled ~20 s of real play as non-gameplay. Fixed in `record.py` and `autopilot2.py`. Detect gameplay with **hysteresis**: banners/popups hide the pause button for 1-4 s, so merge gaps < 5 s and drop segments < 5 s (the Mission Set screen has a yellow header and briefly false-flags).
- Human style: mostly train-roof running, swipe roughly once a second.
- The old `runs/rec_*.json/npz` `play` labels are from the blue-only detector: recompute from `frames` (small-frame pause region: y 7:16, x 2:10) before training.

## 11. Model v1 (imitation CNN) - result: FAILED to generalise
- Code: `~/Documents/subsurf-bot/train.py` (+ `analyze.py`), model file `models/v1.pt`. 3 stacked frames (now, -0.1 s, -0.2 s; 144x64x9) -> 5 classes {none,left,right,up,down}; label = human swipe 0.10-0.30 s ahead; frames within -0.4..+0.1 s of a swipe dropped; mirror-flip aug swaps left/right; class-weighted CE; held-out = whole runs (segments 3 and 7, 84 s of 326 s).
- Data: 2 recordings, 326 s gameplay (10 runs), 222 swipes (76 L / 74 R / 47 up / 25 down) -> 6163 samples (4598 train).
- After 14 epochs: train loss 1.40 -> 0.58 but **val accuracy fell 0.786 -> 0.60** (always-"none" baseline = 0.786), swipe-frame recall 0.22, false-swipe rate 0.30, per-class precision 0.07-0.19. Classic overfitting/memorising. **Do NOT run v1 on the phone.**
- Why: ~1000 highly-correlated positive frames is tiny; the "right" swipe depends on which lane is free, which the net can't learn from this little data; only 2 held-out runs (noisy).
- Next: (a) record 15+ min more, esp. down/up examples; (b) early stopping (best val was epoch 1-4, i.e. it basically predicted "none"), smaller net, more dropout/aug; (c) event-level evaluation; (d) consider RL fine-tuning or a feature-based approach (locate player + free lanes) instead of end-to-end pixels; (e) only test on the phone when val swipe precision/recall clearly beat chance.

## 12. RESUME HERE (new session with more data)
Read `~/Documents/subsurf-bot/PROGRESS.md` (status table, data inventory, resume checklist). Short version: `python3 analyze.py` -> confirm new `runs/rec_*` files -> retrain `.venv/bin/python train.py 14` -> judge on HELD-OUT val numbers only -> improve (early stopping, smaller net, features/RL) -> test on the phone only if it clearly beats chance, with the `in_gameplay()` stop check and no taps on Continue/Ads.

## 13. Recorder v2 (crash-safe) and the lost recording
- An 8-minute recording (16:08) was lost: old `record.py` saved frames then swipes only at the end; the save was interrupted -> truncated `.npz`, no `.json`. Quarantined in `runs/corrupt/`.
- `record.py` now writes swipes live to `<out>.gestures.jsonl` and autosaves frames every 45 s as atomic `<out>.partNNN.npz`; ignores a 2nd Ctrl-C while saving; refuses to overwrite. Load via `dataio.load(base)` / `dataio.discover()` (handles old and new formats). Tell the user: press Ctrl-C ONCE, wait for the `SAVED ...` line.
- ADB drops if the phone's USB mode/debugging changes; USB debugging must be ON (phone in ADB mode `2717:ff08`, not MTP-only `ff40`). After toggling Developer options, the USB debugging switch inside had to be turned on again and re-authorised.

## Model v2 (2026-09-24) - trained on 14.9 min / 651 swipes
- Data: 3 recordings, 896 s gameplay (18 runs), 17,404 samples (12,631 train / 4,773 val; val = 4 whole runs, 250 s). Smaller CNN (16/32/48/48 conv, dropout 0.5/0.3, wd 1e-3), early stopping on val balanced accuracy (patience 5), 25 epochs, ~20 min on CPU (8 threads).
- Best epoch 24: **balanced accuracy 0.468** (random 0.200; v1 ~0.31). Per class on held-out runs: left P0.31/R0.39, right P0.23/R0.36, up P0.37/R0.42, down P0.34/R0.39. False-swipe rate ~22% of no-swipe frames. Accuracy 0.689 vs 0.780 for always-none (class-weighted loss trades accuracy for finding swipes).
- Verdict: real signal (well above chance) but weak; NOT ready to play live. Train loss still falling (0.72), val noisy/plateaued -> more data + augmentation would help most.
- Model file: `models/v2.pt` (contains weights + metadata). Use with `play.py` (dry-run default; `--live` to actually swipe; `--thresh` to trade recall for precision).

## Dry run of model v2 on live human play (2026-09-24, `play.py --compare`, thresh 0.5, cooldown 0.45, 270 s)
- You swiped 154x in gameplay, model would swipe 118x. Event-level (right move within 0.5 s before your swipe): **recall 0.35 (54/154), precision 0.47 (55/118)**.
- Per move (you / found / model / right): left 35/11/24/11, right 34/10/36/10, up 49/22/42/23, down 36/11/16/11. Jump best, right weakest; model **repeats the same action every ~0.5 s in bursts** (inflates false swipes) -> try higher --thresh and longer --cooldown.
- Verdict: not ready for --live. play.py bugs fixed on the way: `train.py` parsed argv at import; loop crashed on the first empty frame (`img is None`).

## Dry run #2 of model v2 (thresh 0.65, cooldown 0.9, 270 s; raw data: runs/dryrun_20260924_172322.json)
- You swiped 215x (0.84/s), model 60x. Recall **0.15**, precision **0.53** (run #1 at thresh 0.5/cd 0.45: recall 0.35, precision 0.47) -> stricter settings trade recall for precision, no net gain.
- vs random-timing baseline (same number of swipes at random times in your play): precision 0.53 vs 0.13 = **4.1x lift**. Per move (model prec vs random): left 0.50/0.13, right 0.45/0.13, up **0.90**/0.17 (n=10), down 0.38/0.06 (n=8). => model has real signal, esp. when to jump; but at confident settings it fires too rarely to play.
- Lesson: dry-run play is NOT saved as training data (frames not recorded). Use `record.py` when the goal is more data.

## Model v3 (2026-09-24) - warm start from v2, 4 recordings (22.1 min gameplay, 1008 swipes, 42,294 frames)
- Data: 25,790 samples; held-out = 6 whole runs (401 s). `train.py <epochs> <tag> [init.pt]`; frames now cached on disk (`runs/_frames_cache.npy`, memmap) because RAM was tight.
- First attempt (from scratch) FAILED: sat at 'always none' (loss 1.405) and my early-stopping counted the plateau as no-improvement -> stopped at epoch 6. Fixed by warm-starting from v2 and evaluating the start model as 'epoch 0'.
- Result: v2 on this held-out set = balanced acc **0.403**; v3 best (epoch 5) = **0.410** -> essentially NO gain from 55% more data (within noise). Train loss kept falling (0.97 -> 0.70), val flat = overfitting. Per class P/R: left .26/.31, right .24/.31, up .34/.34, down .34/.30. Early stopped at epoch 11.
- Machine note: swap was 94% full during training, epochs slowed from ~45 s to ~230 s. Close heavy apps before training.
- Conclusion: end-to-end pixel CNN on ~1000 swipes has plateaued (~0.41). Next: change the approach (features: locate player + free lanes / obstacles, then a small decision model), or RL, or much more varied data. Models on disk: v1 (bad), v2 (0.403 on new val, 0.468 on old val), v3 (0.410).

## Lane-strip model (features.py + train_lanes.py, models/lanes_v1.pt) - option 1 result
- Geometry measured from 28k red-cap detections: camera is FIXED; lanes at x~10/32/53 (64-wide small frame; spacing ~21 px = ~78 px in the 236-wide frame), vanishing point ~(32,40), player row ~112. My earlier `autopilot.py/autopilot2.py` assumed lane spacing 108 px (real ~78), so side lanes fell off-screen -> the 'all lanes blocked' false positives. Cap-based own-lane detection works on ~67% of frames (other outfits have no red cap) -> forward-filled.
- Model: per-lane 16x5 perspective strips (3 lanes x 3 time steps) -> shared per-lane CNN -> decision head + own-lane one-hot; mirror augmentation. ~50x smaller and ~15x faster to train than the pixel CNN (4 s/epoch).
- Held-out (same 6 runs): balanced acc **0.409** (pixel v2 0.403, v3 0.410). Per class P/R: left .24/.29, right .21/.38, up .25/.35, down .26/.29. Early stopped epoch 31, best epoch 23.
- Interpretation: three very different models converge at ~0.41 frame-level balanced accuracy -> likely the ceiling of *imitating noisy human swipes at frame level* (human timing varies by +-0.1-0.2 s, many swipes are optional/gratuitous), not a representation problem. Event-level dry-run of v2 still showed 4x-random precision. Not ready to play live.
- Ideas not yet done: offline EVENT-level evaluation on held-out runs; crash-prediction target (frames before run end); on-device self-play RL fine-tune (needs safe auto-restart, avoid Continue/ads); more varied data.

## First LIVE run of model v2 (2026-09-24, play.py --live --thresh 0.5 --cooldown 0.45)
- Phone was paused mid-run (pause menu: QUIT / RESUME; Mission Set 3). Started bot first (feed ~11 s), then tapped RESUME (phone px ~ (796, 2337)). Bot sent 8 swipes (right, right, left, up x5) in ~14 s; run ended ~22 s after start (crash). Score not read. Bot stopped itself (left gameplay) and sent no taps.
- After the run: mission reward screen ("1,000 COINS" + "Get 2,000 (Ad)"), then tapping "TAP TO CONTINUE" (bottom, ~(539, 2363)) was followed by a full-screen **interstitial ad** (Candy Crush Saga, Install button). LESSON: after a run, do NOT tap through reward/results screens automatically - interstitial ads can follow; leave it to the user, never tap ad UI (Install, skip, X) without explicit OK.
- Account changed by the USER's own play between sessions: coins ~10k -> ~18.7k, keys 5 -> 4, boards 10 -> 17, score multiplier x3.

## Clean live run #2 of model v2 (fresh run from main menu: bot started first, then tapped PLAY at phone px (855, 2343))
- Result: **score 116, 0 coins, run lasted ~12 s**; bot sent 2 swipes (left, left at ~3-4 s) then crashed; stopped itself, no taps sent. Account untouched (4 keys / 17 boards / 18,757 coins). Human best on this account earlier: 416 (x1 multiplier era).
- Live run #1 (resumed a paused human run) score 2,196 is NOT attributable to the bot (run was already in progress). Bot only played the last ~22 s.
- Conclusion: model v2 cannot play a run by itself (2 live runs: dead in 12-22 s). Frame-level ceiling ~0.41 and event-level precision ~0.5 are not enough to survive even the opening obstacles.

## Self-play RL attempt (2026-09-24) - STOPPED by the user: "very poor gameplay, needs so much improvement"
- Built & tested: `screens.py` (classify(): play/menu/dark/other from small frames; `is_results_menu()` strict full-res check: green PLAY btn (0.48) + blue home btn (0.72); rejects pause menu, ads, reward screens, Settings dialog - verified on 10 real screenshots), `rl_loop.py` (REINFORCE from models/v2.pt; taps ONLY PLAY (855,2343) after a verified results menu; stops after 45 s on an unknown screen, runs/STOP file, Ctrl-C), `diag_run.py` (watch one do-nothing run).
- Safety net worked: with the Settings dialog open over the menu the loop stopped and touched nothing.
- Baseline (no learning) 5 episodes, sampling from v2: survived [2.2, 4.4, 2.8, 2.5, 2.0] s (mean 2.8 s), swipes [4,7,1,0,1]. Diagnostic run with NO swipes: play from 0.3 s to ~6.5 s, then a train hit + 'Continue?' dialog -> a do-nothing run lasts ~6 s, so the sampling policy was WORSE than doing nothing, or the loop's episode timer under-counts (unresolved; check t_start/END_OFF_S logic before trusting survival numbers).
- No policy updates were ever run (warmup 5, episodes 5). No learning happened. Conclusion: current v2-based policy is far too weak; RL from it would take a very long time.
- The phone was left at the 'Continue?' dialog after diag_run (never tap it - costs a key; it times out to the results screen).
- If resumed: first fix/verify the episode timer, then consider (a) a much better prior (behaviour cloning with far more data / DAgger-style corrections), (b) a simulator or emulator so RL can run fast, (c) accept hand-written rules for a narrow subset.
