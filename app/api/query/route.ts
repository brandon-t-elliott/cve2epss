// app/api/query/route.ts
import { NextRequest, NextResponse } from 'next/server';

const rateLimitMap = new Map<string, number[]>();

function getClientIp(req: NextRequest): string {
  // Trust the first IP in x-forwarded-for only if behind a reverse proxy
  const forwarded = req.headers.get('x-forwarded-for');
  return forwarded?.split(',')[0].trim() || 'unknown';
}

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const cve = searchParams.get('cve') || '';

  const regex = /^CVE-\d{4}-\d{4,}$/;
  if (!regex.test(cve)) {
    return NextResponse.json({ error: 'Invalid CVE format' }, {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const ip = getClientIp(req);
  const now = Date.now();

  const perUser = rateLimitMap.get(ip) || [];
  const last2s = perUser.filter(ts => now - ts < 2000);
  const last1hr = perUser.filter(ts => now - ts < 60 * 60 * 1000);

  if (last2s.length > 0) {
    return NextResponse.json({ error: 'Rate limit: Please wait 2 seconds between requests' }, {
      status: 429,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  if (last1hr.length >= 100) {
    return NextResponse.json({ error: 'Rate limit: Limited to 100 requests per hour' }, {
      status: 429,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  perUser.push(now);
  rateLimitMap.set(ip, perUser);

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000); // 5s timeout

    const apiRes = await fetch(`https://api.first.org/data/v1/epss?cve=${cve}`, { signal: controller.signal });
    clearTimeout(timeout);

    const apiData = await apiRes.json();

    if (!apiRes.ok || !apiData.data || apiData.data.length === 0) {
      return NextResponse.json({ error: 'No data found for this CVE' }, {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const { epss, percentile } = apiData.data[0];
    return NextResponse.json({ epss, percentile }, {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (err) {
    return NextResponse.json({ error: 'Failed to fetch EPSS data' }, {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
