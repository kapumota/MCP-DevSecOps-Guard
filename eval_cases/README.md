### Casos de evaluación adversarial

`cases.yaml` define el dataset declarativo usado por el harness. El alcance es regresión controlada, no certificación de seguridad, pentest ni prueba exhaustiva.

Categorías principales:

- `benign`: skills válidos que deben permitirse.
- `malicious`: prompt injection, exfiltración, tool poisoning, traversal y tampering.
- `ambiguous`: documentos administrativos o de seguridad que requieren contexto.
- `known_limitations`: casos conservados para mostrar límites conocidos.
