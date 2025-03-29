// app/api/query/route.ts
import { NextRequest, NextResponse } from 'next/server';

const rateLimitMap = new Map<string, number[]>();

function getClientIp(req: NextRequest): string {
  const forwarded = req.headers.get('x-forwarded-for');
  return forwarded?.split(',')[0].trim() || 'unknown';
}

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const cve = searchParams.get('cve') || '';

  const regex = /^CVE-\d{4}-\d{4,10}$/;
  if (!regex.test(cve)) {
    return NextResponse.json({ error: 'Invalid CVE format.' }, {
      status: 400,
      headers: {
        'Content-Type': 'application/json',
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self';"
      }
    });
  }

  const ip = getClientIp(req);
  const now = Date.now();
  const perUser = rateLimitMap.get(ip) || [];
  const last2s = perUser.filter(ts => now - ts < 2000);
  const last1hr = perUser.filter(ts => now - ts < 60 * 60 * 1000);

  if (last2s.length > 0) {
    return NextResponse.json({ error: 'Too many requests. Please wait before sending more.' }, {
      status: 429,
      headers: {
        'Content-Type': 'application/json',
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self';"
      }
    });
  }
  if (last1hr.length >= 100) {
    return NextResponse.json({ error: 'Too many requests. Please wait before sending more.' }, {
      status: 429,
      headers: {
        'Content-Type': 'application/json',
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self';"
      }
    });
  }

  perUser.push(now);
  rateLimitMap.set(ip, perUser);

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const safeCve = encodeURIComponent(cve);
    const apiRes = await fetch(`https://api.first.org/data/v1/epss?cve=${safeCve}`, { signal: controller.signal });
    clearTimeout(timeout);

    const apiData = await apiRes.json();

    if (!apiRes.ok || !apiData.data || apiData.data.length === 0) {
      return NextResponse.json({ error: 'No data found for the specified CVE.' }, {
        status: 404,
        headers: {
          'Content-Type': 'application/json',
          'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self';"
        }
      });
    }

    const { epss, percentile } = apiData.data[0];
    return NextResponse.json({ epss, percentile }, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self';"
      }
    });
  } catch (err) {
    if ((err as any).name === 'AbortError') {
      return NextResponse.json({ error: 'External API request timed out.' }, {
        status: 504,
        headers: {
          'Content-Type': 'application/json',
          'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self';"
        }
      });
    }

    return NextResponse.json({ error: 'An unexpected error occurred.' }, {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self';"
      }
    });
  }
}
