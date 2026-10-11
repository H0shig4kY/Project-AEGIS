# Project AEGIS — Relatório de Validação Técnica

## Sprints 5, 6 e 7 — Ambiente Windows

**Data da validação:** 11 de outubro de 2026  

**Repositório:** https://github.com/H0shig4kY/Project-AEGIS  

**Ramo de referência:** `main`  

**Commit validado:** `0eab38c482a21b4e367cbe2014b748978a8ebed7`  

**Git tree:** `ca3370a6c000c5f1b44953ad819a63d1c42d94fc`  

**Decisão:** APROVADO — COM LIMITAÇÕES DOCUMENTADAS

## 1. Objetivo e âmbito

Este relatório documenta a validação funcional das Sprints 5, 6 e 7 do Project AEGIS em Windows.

A validação incluiu instalação, execução da CLI, testes automatizados, reporting, gestão de evidências, cadeia de custódia, exportação e verificação independente de pacotes.

Os testes manuais foram realizados em assessments descartáveis, com dados sintéticos e sem scans ou reconhecimento ativo de sistemas externos.

Os resultados não constituem uma certificação de segurança nem demonstram ausência de vulnerabilidades fora da cobertura testada.

## 2. Ambiente

| Componente | Configuração |

|---|---|

| Sistema operativo | Windows |

| Terminal | Windows PowerShell |

| Python | 3.13.12 |

| uv | 0.10.9 |

| Pacote | `aegis-pentest==0.1.0` |

| Instalação | Editável, com dependências de desenvolvimento |

| Ambiente virtual | `.venv` |

| Laboratório | `Desktop\\AEGIS-Laboratorio` |

Foi resolvido um impedimento inicial de instalação causado por uma pasta local não rastreada, `aegis/teste1/`, que interferia com a descoberta de pacotes Python. A pasta foi removida após autorização explícita.

## 3. Suite automatizada

Comando executado:

`.\\.venv\\Scripts\\python.exe -m pytest .\\aegis\\tests -q`

| Resultado | Quantidade |

|---|---:|

| Testes aprovados | 1020 |

| Testes ignorados | 3 |

| Testes falhados | 0 |

| Avisos | 1 |

| Duração | 119,73 segundos |

O aviso ocorreu num teste com nomes duplicados num arquivo ZIP malicioso e não provocou falha da suite.

**Limitação de verificabilidade:** estes valores foram observados na saída do terminal durante a sessão e registados neste relatório. O log integral do pytest não está anexado. Por conseguinte, os resultados não podem ser verificados independentemente apenas a partir deste documento; podem ser reproduzidos mediante nova execução da suite no commit de referência.

## 4. Sprint 5 — Reporting

**Resultado: APROVADO NOS CENÁRIOS TESTADOS**

No assessment descartável `Teste-Windows-Sprint7`, foram validados:

\- Inicialização do assessment e consulta do estado.

\- Registo de `example.com` no scope, sem scans.

\- Listagem de findings inicialmente vazia.

\- Relatório JSON com schema 1.

\- Relatório Markdown.

\- Relatório JSON com schema 2.

\- Rejeição de publicação de relatório num destino já existente.

Os relatórios apresentaram contagens coerentes com um assessment sem findings. O schema 2 incluiu as contagens de evidências esperadas.

A revisão manual dos relatórios não cobriu todas as combinações possíveis de findings, estados e evidências.

## 5. Sprint 6 — Evidências

**Resultado: APROVADO NOS CENÁRIOS TESTADOS**

Foi criado o assessment descartável `Demo-Evidencias-Sprint6`.

O finding foi introduzido através de uma fixture offline baseada nas interfaces Python documentadas, não através de um scan.

| Propriedade | Valor |

|---|---|

| Finding ID | `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` |

| Regra | `DEMO\_ONLY` |

| Severidade | `medium` |

| Estado | `active` |

| Asset | `127.0.0.1:443` |

| Natureza | Sintética, sem vulnerabilidade observada |

### 5.1 Evidência local

**Evidence ID:** `c0f0fb55a5f349d78d01dd8ac53c192a`

**Ficheiro:** `capture.txt`

**Tamanho:** 29 bytes

**SHA-256:** `0fc002afab9838e41833c28f359979e10cfdff2701827ebb5430ddcd0adf11fd`

A captura e a associação foram concluídas com sucesso. A verificação da evidência devolveu `status: verified`, e o SHA-256 coincidiu com o calculado independentemente por `Get-FileHash`.

### 5.2 Referência externa

**Evidence ID:** `7913061b3c40424cbf316eeb04e4eff5`

**Origem declarada:** `https://example.test/reference`

A referência foi associada sem recolha de conteúdo externo. A verificação devolveu `reference\_only`, distinguindo corretamente uma referência declarativa de bytes capturados.

### 5.3 Deduplicação e conflitos

A repetição da associação do mesmo ficheiro com os mesmos metadados devolveu o identificador original, sem criar uma nova associação ou evento de custódia.

A tentativa de repetir a associação alterando o motivo de auditoria foi rejeitada:

`Error: Evidence association metadata conflict`

O código de saída foi `1`.

Após a rejeição, foram confirmadas exatamente duas associações: uma `local\_file` e uma `external\_reference`.

A evidência local manteve `status: verified` e a custódia permaneceu na sequência `3`.

## 6. Sprint 7 — Cadeia de custódia

**Resultado: APROVADO NOS CENÁRIOS TESTADOS**

### 6.1 Assessment sem evidências

No assessment `Teste-Windows-Sprint7`, a inicialização e a verificação da cadeia foram concluídas com sucesso.

**Chain ID:** `71acf2c23cae460dac840b18eecf076f`

Resultado observado: `chain\_verified`, sequência `1`, sem anomalias temporais reportadas.

### 6.2 Assessment com evidências

**Chain ID:** `c983bdddc6ec446db1da3099c875d346`

A custódia foi ativada **antes das duas associações de evidência**. A sequência `3` corresponde aos seguintes eventos:

1\. Inicialização da custódia.

2\. Associação da evidência local.

3\. Associação da referência externa.

**Head event SHA-256:** `ab96f92c8f0a34532482a142bdc7cefee235608076e56ea0db4d277c2dca21e4`

A verificação devolveu `chain\_verified`, sequência `3`, sem anomalias temporais reportadas.

A deduplicação e a rejeição de metadados incompatíveis não acrescentaram eventos.

Em ambos os assessments, `external\_checkpoint\_match` foi `null`: não foi utilizado um checkpoint externo de confiança.

### 6.3 Limites de segurança

A cadeia de hashes permite verificar consistência interna, mas não autentica criptograficamente a identidade do operador, a origem dos dados ou os timestamps declarados.

Sem um checkpoint externo de confiança, uma reescrita integral e coerente da cadeia por um agente com controlo suficiente sobre o armazenamento pode não ser detetável apenas através dos hashes internos.

## 7. Sprint 7 — Exportação e verificação independente

**Resultado: APROVADO NOS CENÁRIOS TESTADOS**

Foram testados os perfis `share`, `forensic` e `forensic --include-objects`, inicialmente num assessment sem evidências e depois no assessment com finding sintético e duas associações.

### 7.1 Pacotes com evidências

| Pacote | Tamanho | Integridade | Custódia |

|---|---:|---|---|

| `evidencias-share.zip` | 3 491 bytes | `verified` | `checkpoint\_only` |

| `evidencias-forensic.zip` | 10 069 bytes | `verified` | `chain\_verified` |

| `evidencias-forensic-objects.zip` | 10 560 bytes | `verified` | `chain\_verified` |

Os três pacotes foram exportados e verificados independentemente com `assessment package verify`.

### 7.2 Cobertura

| Propriedade | Share | Forensic | Forensic com objetos |

|---|---|---|---|

| Metadados | `projection\_only` | `verified` | `verified` |

| Evidência local | `content\_not\_included` | `content\_not\_included` | `content\_verified` |

| Referência externa | `reference\_only` | `reference\_only` | `reference\_only` |

O manifesto do pacote forense com objetos confirmou um finding, dois registos de evidência, um objeto capturado de 29 bytes e três eventos de custódia.

O objeto incluído apresentou o SHA-256 esperado.

A verificação dos pacotes não exigiu extração, importação ou acesso à rede.

O perfil `share` é minimizado, mas não garante anonimização. O perfil `forensic` pode conter dados sensíveis em texto simples. Os pacotes não são encriptados.

## 8. Testes negativos

**Resultado: APROVADO NOS CENÁRIOS TESTADOS**

### 8.1 SHA-256 incorreto

Um pacote foi verificado com o hash correto e depois com um hash deliberadamente incorreto.

O hash correto foi aceite; o incorreto foi rejeitado. O ZIP original manteve o seu SHA-256 após a rejeição.

### 8.2 Sobrescrita de pacote existente

Foi tentada uma exportação forense com objetos para um destino já existente.

A operação foi rejeitada. A comparação dos hashes antes e depois devolveu `True`, confirmando que os bytes do ficheiro existente permaneceram inalterados.

A cadeia de custódia manteve `chain\_verified`, sequência `3`.

### 8.3 Metadados incompatíveis

A associação repetida com motivo de auditoria diferente foi rejeitada com código de saída `1`.

Permaneceram duas associações, a evidência local continuou verificada e a cadeia manteve a sequência `3`.

## 9. Estado do repositório

O comando utilizado foi:

`git -C "$HOME\\Desktop\\Project AEGIS" status --short`

A saída vazia confirmou que o Git não reportava alterações locais naquele momento.

**Limitação:** `git status --short` não exclui ficheiros ignorados pelas regras do repositório, como `.venv`, nem constitui uma inspeção exaustiva do sistema de ficheiros.

Os assessments e os pacotes de teste foram criados fora da árvore do repositório.

Não foram efetuadas alterações ao código-fonte durante esta ronda de testes.

## 10. Cenários não exercitados manualmente

\- Corrupção deliberada de objetos de evidência ou registos de custódia.

\- Recuperação explícita de operações de custódia pendentes.

\- Concorrência entre processos durante publicação e leitura.

\- Injeção de falhas de sistema de ficheiros.

\- Limites de quotas e ficheiros de grandes dimensões.

\- Captura de observações provenientes de resultados reais de plugins.

\- Verificação contra checkpoint externo independente.

\- Avaliação aprofundada das ACLs Windows e de adversários com controlo total do armazenamento.

\- Revisão completa dos riscos de correlação ou divulgação nos pacotes `share`.

Alguns destes cenários estão abrangidos pela suite automatizada, mas não foram individualmente reproduzidos na sessão manual descrita.

## 11. Conclusão

A validação Windows demonstrou funcionamento consistente das funcionalidades principais das Sprints 5, 6 e 7 nos cenários executados.

Foram confirmados reporting, gestão e verificação de evidências, deduplicação, rejeição de conflitos, cadeia de custódia, exportação, inspeção e verificação independente de pacotes, bem como a preservação de dados após operações rejeitadas.

Não foram identificados defeitos funcionais nos cenários testados.

Estes resultados não demonstram ausência de defeitos fora da cobertura, autenticação criptográfica de proveniência, proteção contra reescrita integral ou confidencialidade dos pacotes exportados.

## 12. Decisão

**APROVADO — COM LIMITAÇÕES DOCUMENTADAS**

As Sprints 5, 6 e 7 ficam funcionalmente validadas para os cenários automatizados e manuais descritos neste relatório, no ambiente Windows utilizado.

Esta decisão permite encerrar a ronda de validação e fundamentar o planeamento da Sprint 8, sem dispensar auditorias adicionais nem eliminar as limitações identificadas.

---

*Relatório elaborado a partir das saídas da CLI, dos resultados de pytest e da documentação técnica apresentados durante a sessão de validação. O log integral dos testes automatizados não está anexado.*
