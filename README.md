# Appcircle _MobSF Binary Scan_ component

Runs full MobSF static analysis on the app being published: manifest and permissions, certificate
and signing checks, hardcoded secrets, binary protections, network security config, tracker
detection and the scored AppSec report. Scans an **APK, AAB or IPA**.

This is the publish flow step. It takes no artifact path: the app file comes from
`AC_APP_FILE_URL`, which the publish flow sets to the binary being published, and the step
downloads it before scanning. The build workflow counterpart, which scans what the build just
produced, is [appcircle-mobsf-binary-scan](https://github.com/appcircleio/appcircle-mobsf-binary-scan).

MobSF is not shipped with Appcircle and this step never installs it. The runner is provisioned
with MobSF during setup, and the step only locates that installation and drives it through
`mobsf-control.sh`. **Docker is not required.** A runner without MobSF fails the step with the
provisioning script named, since binary analysis has no CLI equivalent to fall back to.

Put it in the publish flow ahead of the store steps (**Send to TestFlight**, **Send to Google
Play**, **Send to Huawei AppGallery**), so a binary that breaks a gate never reaches the store,
and put **Export Publish Artifacts** after it to keep the report downloadable.

## Required Input Variables

None. The app file comes from the publish flow, see [The app file](#the-app-file).

## Optional Input Variables

- `AC_MOBSF_FAIL_ON`: Fail Publish On. `critical` (default), `normal`, `low` or `none`. The
  publish flow breaks on a finding at the selected level **or worse**, so `low` is the strictest
  setting and `critical` the loosest. `none` only reports. The levels map onto MobSF's own
  grades: `critical` is `high`, `normal` is `warning`, `low` is `info`. A `secure` entry is a
  passed check and a `hotspot` needs a human, so neither breaks the flow.
- `AC_MOBSF_MIN_SCORE`: Fail Publish Minimum Security Score. Breaks the flow when MobSF's score
  out of 100 falls below this. `0`, the default, leaves the gate off, since no report can score
  below it. See [The two gates](#the-two-gates).
- `AC_MOBSF_SCAN_TIMEOUT`: Scan Timeout. Seconds for the scan, default `1800`. MobSF's own
  decompile and SAST timeouts are 1000 seconds each, so keep this above their sum. A whole number
  of seconds: a value like `15m` is rejected rather than read as 15 seconds. The scan is
  terminated together with everything it started when it hits the timeout, and the step never
  waits longer than the timeout for it, not even for the MobSF server the control script starts.
- `AC_MOBSF_SAVE_REPORT`: Save Report. Copies the report into the artifacts folder when `true`
  (default).

## The app file

The step reads two variables the publish flow sets on its own, so neither is a step input:

| Variable | Holds |
| --- | --- |
| `AC_APP_FILE_URL` | The signed URL of the app file being published |
| `AC_APP_FILE_NAME` | The file name of that app file, extension included |

The step downloads the URL into its own temp folder under the name from `AC_APP_FILE_NAME`,
falling back to the file name in the URL path when that is empty, and scans the downloaded file.
Redirects are followed, so a CDN that hands the request on is fine.

- **The URL is signed and it expires.** It is never printed: the download command reaches the
  log as `AC_APP_FILE_URL:...` and the signature is stripped from any error the download reports.
  A publish flow that sat on an approval step for longer than the link lives fails here, with
  the expiry named.
- **The name decides the format.** Only `.apk`, `.aab` and `.ipa` are scanned, and anything else
  fails before the download rather than after it.
- **The download is capped at 1800 seconds**, plus 30 seconds to connect. Neither is an input.
- **The downloaded file stays in the step temp folder**, so it is not published as an artifact
  and it does not survive the step.
- The MobSF installation is checked **before** the download, so an unprovisioned runner fails
  without pulling the binary first.

## The two gates

Two independent gates decide the publish flow, and **both are evaluated on every scan**:

| Gate | Input | Reads |
| --- | --- | --- |
| Level gate | `AC_MOBSF_FAIL_ON` (Fail Publish On) | the findings |
| Score gate | `AC_MOBSF_MIN_SCORE` (Fail Publish Minimum Security Score) | the MobSF score out of 100 |

They are not chained, so neither one gates the other:

- Either gate on its own breaks the flow. It fails as soon as one of them is breached,
  whatever the other says.
- `Fail Publish On = none` disables the level gate only. The score gate stays in force, so a score
  below the minimum still breaks the flow.
- A score comfortably above the minimum does not excuse a finding at or above the selected level,
  and a clean level gate does not excuse a low score.
- `0`, the default, leaves the score gate off, and the level gate decides alone.

Whichever gate breaks the flow, the report is published first, so the findings stay downloadable
on the failing path.

## Output Variables

- `AC_MOBSF_SCANNED_ARTIFACT`: The artifact that was scanned.
- `AC_MOBSF_SECURITY_SCORE`: The score out of 100.
- `AC_MOBSF_FINDING_COUNT`, `AC_MOBSF_CRITICAL_COUNT`, `AC_MOBSF_NORMAL_COUNT`,
  `AC_MOBSF_LOW_COUNT`: Finding counts per level.
- `AC_MOBSF_WORST_LEVEL`: `critical`, `normal`, `low`, or `none`.

They are written to `AC_ENV_FILE_PATH` when the runner sets it, and to
`$AC_OUTPUT_DIR/AC_OUTPUT.env` otherwise, which is how a publish step hands values to the steps
after it.

No report path is exported: the report is written straight into `$AC_OUTPUT_DIR` under a fixed
name, so a following step already knows where it is.

## Reports

The report is published directly into `$AC_OUTPUT_DIR` as `mobsf-binary-analyze.json`, under its
own name and unarchived, so add Export Publish Artifacts after this step. It is published on the
failing path too, so a broken gate still leaves the findings downloadable.

JSON is the only format MobSF reports here: its other export is a PDF, which needs
`wkhtmltopdf`, and that is not installed on the runners. There is therefore no output format
input on this step.

The log closes with a summary, ending in the verdict:

```
  Artifact              Battery_8_1_.apk
  Security score        35 / 100
  Critical              6 finding(s)
  Normal                3 finding(s)
  Low                   1 finding(s)
  Passed checks         2
  Needs review          0
  Total                 10 finding(s)
  Worst level found     Critical
  Fail publish on       critical
  Minimum score         0 (no score gate)
  Verdict               pipeline breaks
```

## Notes

- **The whole MobSF interaction is one call.** `mobsf-control.sh --action scan` sources
  `mobsf.env`, starts MobSF if it is not already answering, uploads, scans, writes the report,
  and then removes the scan record, the uploaded artifact and the decompiled sources. That last
  part is why there is no rescan input: MobSF caches by artifact MD5, but the record never
  survives a run, so a stale scan cannot be returned.
- **An AAB is supported.** MobSF converts it to an APK with the bundletool it ships, using the
  provisioned Java.
- A failed decompilation is not a failed scan. MobSF judges jadx by its exit code and jadx exits
  non-zero as soon as one class fails, which is routine for an R8 build. The step reads the
  report rather than the tool's verdict.

## Contributing

Source: https://github.com/appcircleio/appcircle-publish-mobsf-binary-scan
