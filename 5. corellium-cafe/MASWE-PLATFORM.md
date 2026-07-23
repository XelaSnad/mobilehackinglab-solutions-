## MASWE-0072: Universal XSS

This one is quite obviously a feature included to demonstrate that there is opportunity to perform a XSS. 

We can test this POC with a simple javascript script such as 

```html
<script> alert(document.domain) </script> 

```

Clearly there is no form of sanitisation and this pathway leads to arbitrary javascript code execution. 