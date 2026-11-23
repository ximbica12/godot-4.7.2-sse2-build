# Godot 4.7.2 para Windows x64 (SSE2)

Build personalizado do Godot 4.7.2 para CPUs x86-64 antigas, usando o baseline **x86-64-v1 (SSE2)**.

O alvo inicial é o Pentium Dual-Core E5700. A compilação é feita no GitHub Actions, não no computador local.

## O que será gerado

- Executável Windows x64 para rodar jogos empacotados em PCK.
- ISA de base x86-64-v1: SSE2, sem exigir SSE3, SSSE3, SSE4.x, POPCNT ou AVX.
- MinGW-w64 GCC, runtime C/C++ ligado estaticamente.
- LTO desativado para evitar consumo desnecessário de memória no link.
- Vulkan e OpenGL/GLES3 mantidos habilitados; D3D12 e ANGLE desativados para evitar SDKs extras.

O arquivo PCK do jogo não é incluído nem alterado por este repositório.

## Por que existe um patch

No código original do Godot 4.7.2, o bloco x86-64 do `SConstruct` adiciona `-msse4.2` e `-mpopcnt` para GCC/Clang. Isso pode produzir instruções que não existem no Pentium E5700.

O script `scripts/patch_sse2.py` troca essa seleção por `-march=x86-64 -mtune=generic`. Esse é o baseline x86-64-v1, cujo requisito SIMD é SSE2. O workflow também audita o executável final procurando instruções posteriores a SSE2.

Fonte upstream: [Godot 4.7.2-stable / SConstruct](https://github.com/godotengine/godot/blob/4.7.2-stable/SConstruct).

## Compilação

1. Abra a aba **Actions** deste repositório.
2. Selecione **Build Godot 4.7.2 Windows x64 SSE2**.
3. Clique em **Run workflow**.
4. Quando terminar, abra a execução e baixe o artefato `Godot-4.7.2-Windows-x64-SSE2`.

O workflow também roda automaticamente quando os arquivos de configuração do build são alterados na branch `main`.

## Executar um PCK

Coloque o executável baixado na mesma pasta de `MMALife.pck` e execute no PowerShell:

```powershell
.\Godot_v4.7.2-stable_windows_x86_64_SSE2.exe --main-pack ".\MMALife.pck"
```

O build usa `disable_path_overrides=no` para manter disponível a opção de linha de comando `--main-pack` no template de release.

## Limitações importantes

Este build garante que o **executável do Godot** seja compilado para o baseline SSE2. Ele não recompila DLLs, extensões GDExtension ou outros componentes nativos que possam acompanhar o jogo. Esses arquivos podem ter requisitos próprios de CPU e precisarão ser verificados separadamente.

Se o jogo não iniciar, guarde a mensagem de erro completa. Ela ajuda a distinguir uma instrução de CPU ausente de problemas de DLL, driver gráfico ou compatibilidade do próprio jogo.
