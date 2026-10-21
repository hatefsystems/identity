import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle } from '@hatef/ui';
import Link from 'next/link';

export default function Index() {
  return (
    <main className="container flex min-h-screen flex-col items-center justify-center gap-8 py-16">
      <div className="flex flex-col items-center gap-2 text-center">
        <h1 className="text-4xl font-bold tracking-tight">Hatef Identity Platform</h1>
        <p className="max-w-xl text-muted-foreground">
          Centralized, privacy-first Identity Provider (IdP) and unified access portal for the Hatef
          ecosystem.
        </p>
      </div>

      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Welcome</CardTitle>
          <CardDescription>
            Sign in to manage your identity, security settings, and privacy.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <Button asChild className="h-11 w-full">
            <Link href="/login">Sign in</Link>
          </Button>
          <Button asChild variant="outline" className="h-11 w-full">
            <Link href="/register">Create an account</Link>
          </Button>
        </CardContent>
      </Card>
    </main>
  );
}
