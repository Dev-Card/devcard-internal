-- CreateEnum
CREATE TYPE "OrganizerType" AS ENUM ('COMPANY', 'STUDENT_CLUB', 'COMMUNITY', 'NONPROFIT', 'OTHER');

-- CreateEnum
CREATE TYPE "OrganizerStatus" AS ENUM ('PENDING', 'ACTIVE', 'REJECTED');

-- DropForeignKey
ALTER TABLE "events" DROP CONSTRAINT "events_organizerId_fkey";

-- CreateTable
CREATE TABLE "organizer_profiles" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "username" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "password_hash" TEXT NOT NULL,
    "organization_name" TEXT NOT NULL,
    "type" "OrganizerType" NOT NULL,
    "description" TEXT,
    "website" TEXT,
    "logo_url" TEXT,
    "phone_number" TEXT,
    "city" TEXT,
    "country" TEXT,
    "status" "OrganizerStatus" NOT NULL DEFAULT 'PENDING',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "organizer_profiles_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "organizer_profiles_username_key" ON "organizer_profiles"("username");

-- CreateIndex
CREATE UNIQUE INDEX "organizer_profiles_email_key" ON "organizer_profiles"("email");

-- AddForeignKey
ALTER TABLE "events" ADD CONSTRAINT "events_organizerId_fkey" FOREIGN KEY ("organizerId") REFERENCES "organizer_profiles"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
