export declare class EmailService {
    sendVerificationEmail(recipientEmail: string, link: string): Promise<unknown>;
    sendPasswordResetEmail(recipientEmail: string, link: string): Promise<unknown>;
}
