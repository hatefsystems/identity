import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle } from '@hatef/ui';

export default function Index() {
  return (
    <main className="container flex min-h-screen flex-col items-center justify-center gap-8 py-16">
      <div className="flex flex-col items-center gap-2 text-center">
        <h1 className="text-4xl font-bold tracking-tight">Hatef Identity Platform</h1>
        <p className="max-w-xl text-muted-foreground">
          Centralized, privacy-first Identity Provider (IdP) and unified access portal for the
          Hatef ecosystem.
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
          <Button className="w-full">Sign in</Button>
          <Button variant="outline" className="w-full">
            Create an account
          </Button>
        </CardContent>
      </Card>
    </main>
  );
}
