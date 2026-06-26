# Intentionally Vulnerable Lab Fixture

This directory is an opt-in lab fixture for vulnerability-scanner demonstrations.
It is not part of the default public demo, CI install, or developer setup.

`requirements.txt` intentionally pins old vulnerable packages so dependency
scanners have known findings to detect. Do not install it into your normal
development environment.

Safe default paths use mock or synthetic artifacts and do not install or execute
this lab.
