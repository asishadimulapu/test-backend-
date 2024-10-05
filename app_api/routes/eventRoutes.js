// routes/eventRoutes.js

const express = require("express");
const router = express.Router();
const Event = require("../models/Event");

router.get("/getAll", async (req, res) => {
    try {
        const events = await Event.find();
        res.json(events);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

router.get("/get/:id", async (req, res) => {
    try {
        const event = await Event.findById(req.params.id);
        res.json(event);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

router.post("/add", async (req, res) => {
    const event = new Event({
        title: req.body.title,
        location: req.body.location,
        date: req.body.date,
        remind: req.body.remind,
    });
    try {
        const newEvent = await event.save();
        console.log(newEvent);
        res.status(201).json(newEvent);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

router.delete("/delete/:id", async (req, res) => {
    try {
        await Event.findByIdAndDelete(req.params.id);
        res.json({ message: "Event deleted" });
    } catch (error) {
        console.error("Error deleting event:", error);
        res.status(500).json({ message: error.message });
    }
});

router.put("/update/:id", async (req, res) => {
    const eventId = req.params.id;
    const { title, date, location, remind } = req.body;

    try {
        const event = await Event.findById(eventId);
        if (!event) {
            return res.status(404).json({ message: "Event not found" });
        }

        event.title = title;
        event.date = date;
        event.location = location;
        event.remind = remind;

        await event.save();
        console.log(event);
        res.json(event);
    } catch (error) {
        console.error("Error updating event:", error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

module.exports = router;
