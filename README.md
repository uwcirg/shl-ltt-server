# SMART Health Links Demo

## Server

* Demo hosted at https://smart-health-links-server.cirg.washington.edu
* Allows external consumer apps to create a SHL and add files to it
* Allows SHL clients to connect and pull data from any active SHL

## UI

* Demo hosted at https://smart-health-links-demo.cirg.washington.edu
* Simulates a state immunization portal or consumer health wallet UX
  * Comes with a built-in set of immunizations (synthetic data for a school-age child)
* Connects to server component for backend storage

## Client
* Deployed SHL content viewer app hosted at https://smart-health-links-demo.cirg.washington.edu
* Deployed library hosted at https://smart-health-links-demo.cirg.washington.edu/index.js
* Generic library that supports
  * Inspecting a SHL with the `.flags({shl: "shlink:/..."})` function
  * Connecting to a SHL with the `.connect({shl: "shlink:/..."})` function
  * Pulling data from a SHL with the `.pull(connection)` function
