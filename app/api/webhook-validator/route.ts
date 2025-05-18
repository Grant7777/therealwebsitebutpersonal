import crypto from 'crypto';

// Environment variable for the webhook secret
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

if (typeof WEBHOOK_SECRET !== 'string') {
  throw new Error('WEBHOOK_SECRET is not set or is not a string');
}

// Function to verify the signature
async function verifySignature(request: Request): Promise<boolean> {
  const payload = await request.text();
  const signature = crypto
    .createHmac('sha1', WEBHOOK_SECRET)
    .update(payload)
    .digest('hex');
  return signature === request.headers.get('x-vercel-signature');
}

// Main handler function
export async function POST(request: Request) {
  // Verify the signature
  const isValid = await verifySignature(request);

  if (!isValid) {
    return Response.json({
      code: 'invalid_signature',
      error: "Signature didn't match",
    }, { status: 401 });
  }

  // Re-read the body as we've already consumed it in verifySignature
  const rawBody = await request.text();
  const json = JSON.parse(rawBody);

  // Process different event types
  switch (json.type) {
    case 'project.created':
      // Handle project creation
      console.log('Project created:', json.project.name);
      break;
    case 'deployment.created':
      // Handle deployment creation
      console.log('Deployment created:', json.deployment.url);
      break;
    // Add more cases as needed
    default:
      console.log('Unhandled event type:', json.type);
  }

  return new Response('Webhook processed successfully', { status: 200 });
}

// Helper function to handle errors
function handleError(error: Error) {
  console.error('Error processing webhook:', error);
  return Response.json({
    code: 'internal_server_error',
    error: 'An unexpected error occurred',
  }, { status: 500 });
}

// Wrapper to catch any unexpected errors
export async function handler(request: Request) {
  try {
    return await POST(request);
  } catch (error) {
    return handleError(error as Error);
  }
}
