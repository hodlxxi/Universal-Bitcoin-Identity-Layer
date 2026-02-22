
## Update: Surgical CSS Override (Dec 16, 2025)

### Issue
Landing page had 52 conflicting background declarations blocking Matrix animation.

### Solution
Injected CSS override block after landing's inline `<style>`:
- Remapped color tokens to ui_core values
- Disabled old `.matrix-canvas` elements
- Forced glass panel aesthetic on all cards
- Applied backdrop blur to navigation

### Files Modified
- `app/app.py` - Added `UI_CORE_LANDING_OVERRIDE` style block

### Backups
- `app/app.py.bak.landing-unify-2025-12-16-*`

### Result
Landing page now has unified HODLXXI aesthetic with Matrix background.
