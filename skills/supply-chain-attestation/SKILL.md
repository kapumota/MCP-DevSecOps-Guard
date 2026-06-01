---
name: supply-chain-attestation
description: Usar este skill para empaquetar SBOM, reportes de scan, evidencia tipo in-toto/SLSA y procedencia de release.
---

### Skill de atestación de supply chain

#### Goal

Crear un paquete de evidencia que respalde una afirmación reproducible de seguridad de supply chain.

#### Inputs

- SBOM generados por Syft.
- Evidencia SAST, SCA, image scan, DAST y smoke tests.
- Archivos locales opcionales tipo in-toto/SLSA.
- Objetivo actual de release o demo.

#### Procedure

1. Ejecutar o verificar `make sbom`, `make scan-image`, `make sast`, `make sca` y `make evidence-pack`.
2. Confirmar que el bundle incluye SBOM de proyecto, SBOM de imagen, auditoría de dependencias, SAST, container scan, DAST y evidencia de humo.
3. Declarar qué prueba la evidencia y qué no prueba.
4. Identificar anclas de confianza faltantes: procedencia firmada, gestión de claves, atestación de registry, builds herméticos y digests reproducibles.
5. Recomendar el menor siguiente paso para mejorar aseguramiento.

#### Output Format

- Inventario de evidencia.
- Afirmaciones de aseguramiento.
- Brechas.
- Siguiente paso de hardening.

#### Safety Limits

- No afirmar procedencia, firmas ni confianza de registry sin evidencia correspondiente.
- No solicitar secretos, claves de firma ni credenciales.
- Usar solo artifacts locales y comandos permitidos del proyecto.

#### Acceptance Criteria

- El inventario nombra los artifacts esperados y marca evidencia faltante.
- Las afirmaciones se limitan a lo que el pipeline local demuestra.
- Las brechas distinguen reproducibilidad, integridad, procedencia y cobertura runtime.
- La recomendación final es accionable dentro del repositorio actual.
