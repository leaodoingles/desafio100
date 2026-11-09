/**
 * D100 — recebe o aviso (webhook) da Kiwify e repassa pro Apps Script.
 *
 * Por que isso existe: a Kiwify trata qualquer redirecionamento como falha, e o Apps Script
 * sempre responde com um redirecionamento. Esta função fica no meio: confere que o aviso veio
 * mesmo da Kiwify, repassa pro Apps Script (servidor com servidor) e responde 200 pra Kiwify.
 *
 * Variáveis de ambiente (Vercel > Settings > Environment Variables):
 *   KIWIFY_TOKEN     token do webhook, o mesmo cadastrado na Kiwify
 *   APPS_SCRIPT_URL  endereço /exec do Apps Script
 *   D100_CHAVE       chave interna, igual à CHAVE_KIWIFY do código do Apps Script
 *
 * Endereço pra cadastrar na Kiwify:  https://SEU-SITE.vercel.app/api/kiwify
 * (a Kiwify acrescenta ?signature=... sozinha)
 */
const crypto = require('crypto');

async function lerCorpoBruto(req) {
  const partes = [];
  for await (const pedaco of req) partes.push(typeof pedaco === 'string' ? Buffer.from(pedaco) : pedaco);
  return Buffer.concat(partes);
}

// Confere a assinatura: HMAC-SHA1 (hex) do corpo EXATO recebido, usando o token como chave
function assinaturaValida(corpo, recebida, token) {
  const esperada = crypto.createHmac('sha1', token).update(corpo).digest('hex');
  const a = Buffer.from(String(recebida || ''));
  const b = Buffer.from(esperada);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ ok: false });

  const token = process.env.KIWIFY_TOKEN;
  const url = process.env.APPS_SCRIPT_URL;
  const chave = process.env.D100_CHAVE;
  if (!token || !url || !chave) return res.status(500).json({ ok: false, erro: 'configuracao' });

  const corpo = await lerCorpoBruto(req);
  const assinatura = new URL(req.url, 'http://localhost').searchParams.get('signature');
  if (!assinaturaValida(corpo, assinatura, token)) return res.status(401).json({ ok: false });

  try {
    const resp = await fetch(url, {
      method: 'POST',
      body: new URLSearchParams({ acao: 'kiwify', chave, payload: corpo.toString('utf8') }),
      redirect: 'follow',
    });
    const dados = await resp.json().catch(() => null);
    // 200 só quando o Apps Script confirmou; senão a Kiwify tenta de novo sozinha
    if (dados && dados.ok === true) return res.status(200).json({ ok: true });
    return res.status(502).json({ ok: false });
  } catch (e) {
    return res.status(502).json({ ok: false });
  }
}

module.exports = handler;
module.exports.assinaturaValida = assinaturaValida;
// Precisamos do corpo BRUTO (a assinatura é calculada em cima dele), então desligamos o parser automático.
module.exports.config = { api: { bodyParser: false } };
